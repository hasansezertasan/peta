"""Unit tests for the built-in enrichment provider adapters.

Each adapter is checked for the mapping it owns: client outcome to provider
state, evidence, and reason. The clients themselves are patched at their own
module boundary, never at the HTTP layer.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock, patch

import pytest

from peta.core.cache import Provenance
from peta.core.models import PackageInfo, Vulnerability
from peta.core.providers import (
    CAPABILITY_FIELDS,
    CAPABILITY_GROUPS,
    DEFAULT_PROVIDERS,
    CountEvidence,
    LibrariesIoProvider,
    OsvProvider,
    ProviderResult,
    PypiStatsProvider,
    VulnerabilityEvidence,
)
from peta.core.validation import EnrichmentError

if TYPE_CHECKING:
    from peta.core.output import SourceState
    from peta.core.providers import Capability

pytestmark = pytest.mark.unit

_LIVE = Provenance("live", "2026-01-01T00:00:00Z")


def _bare_result() -> ProviderResult:
    """Build a minimal valid result to mutate into an invalid one.

    Returns:
        A result carrying no evidence and no warnings.
    """
    return ProviderResult(
        provider="bad", capability="download_count", state="empty", subject="requests"
    )


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(name="requests", version="2.31.0", source="local")
    return replace(base, **over)


class TestOsvProvider:
    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
    def test_success_carries_typed_evidence(self, mo: MagicMock) -> None:
        mo.return_value = [
            Vulnerability(id="GHSA-1", aliases=[], summary="s", fixed_in=["1.1"])
        ]
        result = OsvProvider().fetch(_pkg())
        assert result.state == "success"
        assert result.evidence == VulnerabilityEvidence(mo.return_value)
        assert result.field == "result.vulnerabilities"
        assert result.subject == "requests"
        assert result.retrieved_at is not None
        mo.assert_called_once_with("requests", "2.31.0")

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities", return_value=[])
    def test_no_advisories_is_empty_not_failed(self, mo: MagicMock) -> None:
        result = OsvProvider().fetch(_pkg())
        # A clean lookup is "empty", never a silent success with no data.
        assert result.state == "empty"
        assert result.evidence == VulnerabilityEvidence([])
        mo.assert_called_once()

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
    def test_client_error_becomes_a_failed_result(self, mo: MagicMock) -> None:
        mo.side_effect = EnrichmentError("osv", "HTTP 503")
        result = OsvProvider().fetch(_pkg())
        # A provider reports failure; it must never raise into orchestration.
        assert result.state == "failed"
        assert result.reason == "HTTP 503"
        assert result.evidence is None


class TestPypiStatsProvider:
    @patch(
        "peta.core.providers.builtin.stats.get_download_count",
        return_value=(1234, _LIVE),
    )
    def test_success_carries_count_evidence(self, m: MagicMock) -> None:
        result = PypiStatsProvider().fetch(_pkg())
        assert result.state == "success"
        assert result.evidence == CountEvidence(1234)
        assert result.field == "result.download_count"
        m.assert_called_once_with("requests")

    @patch(
        "peta.core.providers.builtin.stats.get_download_count",
        return_value=(None, _LIVE),
    )
    def test_missing_count_is_empty(self, m: MagicMock) -> None:
        result = PypiStatsProvider().fetch(_pkg())
        assert result.state == "empty"
        assert result.evidence is None
        m.assert_called_once()

    @patch("peta.core.providers.builtin.stats.get_download_count")
    def test_client_error_becomes_a_failed_result(self, m: MagicMock) -> None:
        m.side_effect = EnrichmentError("pypistats", "HTTP 429")
        result = PypiStatsProvider().fetch(_pkg())
        assert result.state == "failed"
        assert result.reason == "HTTP 429"


class TestLibrariesIoProvider:
    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch("peta.core.providers.builtin.stats.libraries_io_api_key", return_value=None)
    def test_missing_api_key_is_unavailable_without_a_request(
        self, mkey: MagicMock, mdep: MagicMock
    ) -> None:
        result = LibrariesIoProvider().fetch(_pkg())
        # "Not configured" must stay distinct from "returned nothing".
        mkey.assert_called_once_with()
        assert result.state == "unavailable"
        assert result.reason == "LIBRARIES_IO_API_KEY is not configured"
        assert result.retrieved_at is None
        mdep.assert_not_called()

    @patch(
        "peta.core.providers.builtin.stats.get_dependent_count",
        return_value=(42, _LIVE),
    )
    @patch(
        "peta.core.providers.builtin.stats.libraries_io_api_key", return_value="secret"
    )
    def test_success_passes_the_key_through(
        self, mkey: MagicMock, mdep: MagicMock
    ) -> None:
        result = LibrariesIoProvider().fetch(_pkg())
        mkey.assert_called_once_with()
        assert result.state == "success"
        assert result.evidence == CountEvidence(42)
        mdep.assert_called_once_with("requests", api_key="secret")

    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch(
        "peta.core.providers.builtin.stats.libraries_io_api_key", return_value="secret"
    )
    def test_client_error_becomes_a_failed_result(
        self, mkey: MagicMock, mdep: MagicMock
    ) -> None:
        mdep.side_effect = EnrichmentError("libraries.io", "invalid JSON")
        result = LibrariesIoProvider().fetch(_pkg())
        mkey.assert_called_once_with()
        assert result.state == "failed"
        assert result.reason == "invalid JSON"


def test_default_registry_covers_every_capability_exactly_once() -> None:
    capabilities = [provider.capability for provider in DEFAULT_PROVIDERS]
    assert sorted(capabilities) == [
        "dependent_count",
        "download_count",
        "vulnerabilities",
    ]


def test_default_registry_groups_match_the_cli_opt_out_flags() -> None:
    groups = {
        provider.name: CAPABILITY_GROUPS[provider.capability]
        for provider in DEFAULT_PROVIDERS
    }
    assert groups == {
        "osv": "vulnerabilities",
        "pypistats": "stats",
        "libraries.io": "stats",
    }


def test_every_capability_maps_to_an_opt_out_group() -> None:
    # A capability with no group would silently escape both --no-osv and
    # --no-stats, so the map must stay total over Capability.
    assert set(CAPABILITY_GROUPS) == set(CAPABILITY_FIELDS)


def test_group_follows_the_capability_not_the_provider() -> None:
    # A provider cannot declare a group, so it cannot file a count under the
    # vulnerability family to dodge --no-stats.
    assert CAPABILITY_GROUPS["download_count"] == "stats"
    assert CAPABILITY_GROUPS["dependent_count"] == "stats"
    assert CAPABILITY_GROUPS["vulnerabilities"] == "vulnerabilities"


def test_an_unknown_capability_has_no_attributable_field() -> None:
    # An injected provider can declare a capability outside the Literal at
    # runtime; the result must not invent a field for it.
    result = ProviderResult(
        provider="stranger",
        capability=cast("Capability", "made_up"),
        state="failed",
        subject="requests",
        reason="provider declares unknown capability 'made_up'",
    )
    assert result.field is None


class TestResultVariantValidation:
    """A result whose parts disagree is rejected where it is built."""

    def test_evidence_must_match_its_capability(self) -> None:
        # Would otherwise write dependent_count while claiming
        # result.vulnerabilities in provenance.
        with pytest.raises(TypeError, match="does not match capability"):
            ProviderResult(
                provider="bad",
                capability="vulnerabilities",
                state="success",
                subject="requests",
                evidence=CountEvidence(1),
            )

    @pytest.mark.parametrize(
        "state", ["failed", "skipped", "unavailable", "unsupported"]
    )
    def test_absent_answer_states_cannot_carry_an_answer(
        self, state: SourceState
    ) -> None:
        with pytest.raises(ValueError, match="cannot carry an answer"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state=state,
                subject="requests",
                evidence=CountEvidence(1),
            )

    @pytest.mark.parametrize(
        "state", ["failed", "skipped", "unavailable", "unsupported"]
    )
    def test_absent_answer_states_cannot_carry_empty_evidence_either(
        self, state: SourceState
    ) -> None:
        with pytest.raises(ValueError, match="cannot carry evidence"):
            ProviderResult(
                provider="bad",
                capability="vulnerabilities",
                state=state,
                subject="requests",
                evidence=VulnerabilityEvidence([]),
            )

    def test_success_must_carry_an_answer(self) -> None:
        with pytest.raises(ValueError, match="must carry a non-empty answer"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state="success",
                subject="requests",
            )

    def test_success_cannot_claim_an_empty_answer(self) -> None:
        # Would report "found advisories" while merging none.
        with pytest.raises(ValueError, match="must carry a non-empty answer"):
            ProviderResult(
                provider="bad",
                capability="vulnerabilities",
                state="success",
                subject="requests",
                evidence=VulnerabilityEvidence([]),
            )

    def test_empty_cannot_carry_a_real_answer(self) -> None:
        # Would merge a count while provenance claims the source had none.
        with pytest.raises(ValueError, match="cannot carry an answer"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state="empty",
                subject="requests",
                evidence=CountEvidence(5),
            )

    @pytest.mark.parametrize("reason", [None, "", "   "])
    def test_failed_must_carry_a_diagnostic(self, reason: str | None) -> None:
        with pytest.raises(ValueError, match="must carry a reason"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state="failed",
                subject="requests",
                reason=reason,
            )

    @pytest.mark.parametrize("reason", [None, "", "   "])
    def test_unsupported_must_carry_a_diagnostic(self, reason: str | None) -> None:
        with pytest.raises(ValueError, match="must carry a reason"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state="unsupported",
                subject="requests",
                reason=reason,
            )

    @pytest.mark.parametrize("state", ["bogus", "", "SUCCESS"])
    def test_an_undocumented_state_is_rejected(self, state: str) -> None:
        # An annotation does not stop a runtime string, and an undocumented
        # state would otherwise reach the envelope unchallenged.
        with pytest.raises(ValueError, match="not a documented source state"):
            ProviderResult(
                provider="bad",
                capability="download_count",
                state=cast("SourceState", cast("object", state)),
                subject="requests",
            )

    def test_empty_may_carry_empty_evidence(self) -> None:
        result = ProviderResult(
            provider="osv",
            capability="vulnerabilities",
            state="empty",
            subject="requests",
            evidence=VulnerabilityEvidence([]),
        )
        assert result.evidence == VulnerabilityEvidence([])

    @pytest.mark.parametrize("item", [None, {"id": "GHSA-1"}])
    def test_vulnerability_evidence_rejects_a_malformed_item(
        self, item: object
    ) -> None:
        # `_merge` reads `.id`/`.aliases` off every item; an item that is not a
        # `Vulnerability` would otherwise reach it as an unguarded
        # `AttributeError`, discarding the whole package.
        with pytest.raises(TypeError, match="Vulnerability instances"):
            VulnerabilityEvidence(cast("list[Vulnerability]", [item]))

    def test_vulnerability_evidence_rejects_unhashable_id(self) -> None:
        vuln = Vulnerability(
            id=cast("str", ["not", "a", "string"]), aliases=[], summary="s", fixed_in=[]
        )
        with pytest.raises(TypeError, match="id and aliases must be strings"):
            VulnerabilityEvidence([vuln])

    def test_vulnerability_evidence_rejects_unhashable_alias(self) -> None:
        vuln = Vulnerability(
            id="GHSA-1",
            aliases=cast("list[str]", [["nested"]]),
            summary="s",
            fixed_in=[],
        )
        with pytest.raises(TypeError, match="id and aliases must be strings"):
            VulnerabilityEvidence([vuln])

    def test_vulnerability_evidence_accepts_genuine_vulnerabilities(self) -> None:
        vuln = Vulnerability(id="GHSA-1", aliases=[], summary="s", fixed_in=[])
        evidence = VulnerabilityEvidence([vuln])
        assert evidence.vulnerabilities == [vuln]

    def test_vulnerability_evidence_accepts_an_empty_list(self) -> None:
        assert VulnerabilityEvidence([]).vulnerabilities == []

    @pytest.mark.parametrize("count", [None, "5", 1.0, True, False])
    def test_count_evidence_rejects_a_non_integer(self, count: object) -> None:
        # A malformed count would otherwise reach `PackageInfo.download_count`
        # and only fail later, e.g. at table-rendering time.
        with pytest.raises(TypeError, match="non-boolean int"):
            CountEvidence(cast("int", count))

    def test_count_evidence_accepts_a_genuine_int(self) -> None:
        assert CountEvidence(0).count == 0

    def test_warnings_rejects_none(self) -> None:
        # Built with ``replace`` rather than a cast, for the same reason as
        # the freshness check: it re-runs __post_init__, so the guard is
        # exercised without a string cast that hides the type from analysis.
        with pytest.raises(TypeError, match="warnings must be a list"):
            _ = replace(_bare_result(), warnings=None)

    def test_warnings_rejects_a_malformed_item(self) -> None:
        with pytest.raises(TypeError, match="ProviderWarning instances"):
            _ = replace(_bare_result(), warnings=[{"source": "x"}])


class TestFreshnessValidation:
    def test_a_documented_origin_is_accepted(self) -> None:
        result = ProviderResult(
            provider="pypistats",
            capability="download_count",
            state="success",
            subject="requests",
            freshness="cached",
            evidence=CountEvidence(1),
        )
        assert result.freshness == "cached"

    def test_an_undocumented_origin_is_rejected(self) -> None:
        # An injected provider can put any string here despite the annotation,
        # and it would otherwise reach the envelope as an undocumented value.
        # Built with ``replace`` rather than a cast: it re-runs __post_init__,
        # so the check is exercised without asking the type checkers to
        # pretend an invalid literal is valid.
        valid = ProviderResult(
            provider="pypistats",
            capability="download_count",
            state="success",
            subject="requests",
            freshness="live",
            evidence=CountEvidence(1),
        )
        with pytest.raises(ValueError, match="not a documented origin"):
            _ = replace(valid, freshness="probably-fine")

    def test_no_stated_origin_is_allowed(self) -> None:
        # A source with no retrieval to speak of, such as one that was never
        # consulted, has no origin to report.
        result = ProviderResult(
            provider="libraries.io",
            capability="dependent_count",
            state="unavailable",
            subject="requests",
            reason="LIBRARIES_IO_API_KEY is not configured",
        )
        assert result.freshness is None


class TestFailureProvenance:
    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
    def test_a_source_that_was_reached_records_when(self, mo: MagicMock) -> None:
        mo.side_effect = EnrichmentError("osv", "HTTP 503")
        result = OsvProvider().fetch(_pkg())
        assert result.state == "failed"
        assert result.retrieved_at is not None

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
    def test_a_source_never_contacted_claims_no_time(self, mo: MagicMock) -> None:
        # Offline refuses before anything is sent, so there is no retrieval to
        # timestamp; claiming one would say a request happened when none did.
        mo.side_effect = EnrichmentError("osv", "offline", contacted=False)
        result = OsvProvider().fetch(_pkg())
        assert result.state == "failed"
        assert result.retrieved_at is None
