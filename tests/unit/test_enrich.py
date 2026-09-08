"""Unit tests for enrichment orchestration over in-memory fake providers.

These exercise orchestration only: no HTTP module is patched, so a provider's
transport is irrelevant here and covered by its own client tests.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, cast

import pytest

from peta.core.enrich import enrich
from peta.core.models import (
    VULNERABILITY_FIELD,
    EnrichmentFailure,
    PackageInfo,
    ProviderConflict,
    ProviderWarning,
    Vulnerability,
)
from peta.core.output import utc_now
from peta.core.providers import (
    Capability,
    CountEvidence,
    Evidence,
    ProviderResult,
    VulnerabilityEvidence,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from peta.core.output import SourceState

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(name="requests", version="2.31.0", source="local")
    return replace(base, **over)


@dataclass
class FakeProvider:
    """An in-memory provider returning a canned result and recording calls."""

    name: str
    capability: Capability
    state: SourceState = "success"
    evidence: Evidence | None = None
    reason: str | None = None
    retrieved_at: str | None = "2026-09-04T12:00:00Z"
    warnings: list[ProviderWarning] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    fetch_impl: Callable[[PackageInfo], ProviderResult] | None = None
    """Optional behaviour, for tests about *when* a provider runs.

    The canned fields describe what a provider returns; a few tests need to
    control how long it takes or observe that it overlaps another, which a
    fixed value cannot express.
    """

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Record the call and return the canned result.

        Returns:
            The configured provider result.
        """
        self.calls.append(pkg.name)
        if self.fetch_impl is not None:
            return self.fetch_impl(pkg)
        return ProviderResult(
            provider=self.name,
            capability=self.capability,
            state=self.state,
            subject=pkg.name,
            retrieved_at=self.retrieved_at,
            evidence=self.evidence,
            reason=self.reason,
            warnings=self.warnings,
        )


class _Impostor:
    """Returns a result attributed to a provider other than itself."""

    name = "honest"
    capability: Capability = "download_count"

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Return a result claiming to come from somewhere else.

        Returns:
            A result whose ``provider`` does not match this provider.
        """
        return ProviderResult(
            provider="somewhere-else",
            capability="download_count",
            state="success",
            subject=pkg.name,
            retrieved_at="2026-09-04T12:00:00Z",
            evidence=CountEvidence(999),
        )


class _CapabilityForger:
    """Declares one capability and answers with another."""

    name = "forger"
    capability: Capability = "vulnerabilities"

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Return a count result from a declared vulnerability provider.

        Returns:
            A self-consistent result for a capability this provider does not
            declare.
        """
        return ProviderResult(
            provider="forger",
            capability="download_count",
            state="success",
            subject=pkg.name,
            retrieved_at="2026-09-04T12:00:00Z",
            evidence=CountEvidence(999),
        )


def _vuln(identifier: str) -> Vulnerability:
    return Vulnerability(id=identifier, aliases=[], summary="s", fixed_in=["1.1"])


def _osv(**over: object) -> FakeProvider:
    base = FakeProvider(
        name="osv",
        capability="vulnerabilities",
        evidence=VulnerabilityEvidence([_vuln("GHSA-1")]),
    )
    return replace(base, **over)


def _downloads(count: int = 100, **over: object) -> FakeProvider:
    base = FakeProvider(
        name="pypistats", capability="download_count", evidence=CountEvidence(count)
    )
    return replace(base, **over)


def _dependents(count: int = 5, **over: object) -> FakeProvider:
    base = FakeProvider(
        name="libraries.io", capability="dependent_count", evidence=CountEvidence(count)
    )
    return replace(base, **over)


class TestEnrich:
    def test_merges_provider_evidence(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=False,
            providers=[_osv(), _downloads(), _dependents()],
        )
        assert [v.id for v in pkg.vulnerabilities] == ["GHSA-1"]
        assert pkg.download_count == 100
        assert pkg.dependent_count == 5
        assert [source.state for source in pkg.enrichment_sources] == [
            "success",
            "success",
            "success",
        ]

    def test_source_records_carry_capability_fields(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=False,
            providers=[_osv(), _downloads(), _dependents()],
        )
        assert [source.fields for source in pkg.enrichment_sources] == [
            ["result.vulnerabilities"],
            ["result.download_count"],
            ["result.dependent_count"],
        ]

    def test_no_osv_skips_only_the_vulnerability_group(self) -> None:
        osv, downloads = _osv(), _downloads()
        pkg = enrich(_pkg(), no_osv=True, no_stats=False, providers=[osv, downloads])
        assert osv.calls == []
        assert downloads.calls == ["requests"]
        assert pkg.vulnerabilities == []
        assert pkg.download_count == 100
        assert pkg.enrichment_sources[0].state == "skipped"

    def test_no_stats_skips_only_the_stats_group(self) -> None:
        osv, downloads, dependents = _osv(), _downloads(), _dependents()
        pkg = enrich(
            _pkg(), no_osv=False, no_stats=True, providers=[osv, downloads, dependents]
        )
        assert osv.calls == ["requests"]
        assert downloads.calls == []
        assert dependents.calls == []
        assert pkg.download_count is None
        assert [source.state for source in pkg.enrichment_sources] == [
            "success",
            "skipped",
            "skipped",
        ]

    def test_records_confirmed_empty_result(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[_osv(state="empty", evidence=VulnerabilityEvidence([]))],
        )
        source = pkg.enrichment_sources[0]
        assert source.state == "empty"
        assert source.retrieved_at is not None
        assert source.fields == ["result.vulnerabilities"]

    def test_records_partial_failures(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=False,
            providers=[
                _osv(state="failed", evidence=None, reason="invalid $.vulns"),
                _downloads(state="failed", evidence=None, reason="HTTP 503"),
                _dependents(state="failed", evidence=None, reason="invalid JSON"),
            ],
        )
        assert pkg.enrichment_failures == [
            EnrichmentFailure(
                source="osv", reason="invalid $.vulns", field=VULNERABILITY_FIELD
            ),
            EnrichmentFailure(
                source="pypistats", reason="HTTP 503", field="result.download_count"
            ),
            EnrichmentFailure(
                source="libraries.io",
                reason="invalid JSON",
                field="result.dependent_count",
            ),
        ]
        assert pkg.vulnerabilities == []
        assert pkg.download_count is None
        assert pkg.dependent_count is None

    def test_one_provider_failure_keeps_another_provider_evidence(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=False,
            providers=[
                _osv(state="failed", evidence=None, reason="HTTP 500"),
                _downloads(),
                _dependents(state="failed", evidence=None, reason="HTTP 503"),
            ],
        )
        # The surviving provider's evidence must not be erased by its neighbours.
        assert pkg.download_count == 100
        assert [failure.source for failure in pkg.enrichment_failures] == [
            "osv",
            "libraries.io",
        ]

    def test_failures_record_the_field_the_source_would_have_written(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[
                _osv(name="ghsa", state="failed", evidence=None, reason="HTTP 503")
            ],
        )
        # Recorded by field, so an alternate advisory source is still
        # recognisable as "the vulnerability lookup failed".
        assert pkg.enrichment_failures[0].field == "result.vulnerabilities"
        assert pkg.vulnerabilities_unknown

    def test_a_raising_provider_is_contained(self) -> None:
        class Exploding:
            name = "boom"
            capability: Capability = "dependent_count"

            def fetch(self, pkg: PackageInfo) -> ProviderResult:
                msg = f"kaboom on {pkg.name}"
                raise RuntimeError(msg)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[Exploding(), downloads]
        )
        # enrich promises never to raise, and a bad provider must not stop
        # the providers queued behind it.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "boom"
        assert failure.field == "result.dependent_count"
        assert "RuntimeError: kaboom on requests" in failure.reason
        assert pkg.enrichment_sources[0].state == "failed"

    def test_a_result_for_another_capability_is_rejected(self) -> None:
        # A declared vulnerability provider must not answer with a count:
        # its group follows its capability, so --no-stats skipped it and the
        # returned field was never consulted for.
        pkg = enrich(
            _pkg(), no_osv=False, no_stats=True, providers=[_CapabilityForger()]
        )
        assert pkg.download_count is None
        failure = pkg.enrichment_failures[0]
        assert failure.source == "forger"
        assert "capability" in failure.reason
        # Attributed to what the provider declared, not what it returned.
        assert failure.field == "result.vulnerabilities"

    def test_a_result_attributed_to_another_provider_is_rejected(self) -> None:
        pkg = enrich(_pkg(), no_osv=True, no_stats=False, providers=[_Impostor()])
        assert pkg.download_count is None
        failure = pkg.enrichment_failures[0]
        assert failure.source == "honest"
        assert "attributed to" in failure.reason

    def test_a_completed_lookup_without_a_timestamp_is_stamped(self) -> None:
        # The contract promises a retrieval time; good evidence must not be
        # discarded just because the provider forgot to stamp it.
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[_downloads(retrieved_at=None)],
        )
        assert pkg.download_count == 100
        source = pkg.enrichment_sources[0]
        assert source.state == "success"
        assert source.retrieved_at is not None

    def test_a_provider_declaring_an_unknown_capability_is_contained(self) -> None:
        class Stranger:
            name = "stranger"
            capability = cast("Capability", "made_up")

            def fetch(self, pkg: PackageInfo) -> ProviderResult:  # pragma: no cover
                msg = f"should not be consulted for {pkg.name}"
                raise AssertionError(msg)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[Stranger(), downloads]
        )
        # No opt-out flag can gate an unknown capability, so the provider is
        # rejected before it is consulted rather than run ungated.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "stranger"
        assert failure.reason == "provider declares unknown capability 'made_up'"
        # Unattributable, so it claims no result field.
        assert failure.field is None
        assert pkg.enrichment_sources[0].fields == []

    def test_a_provider_whose_metadata_raises_is_contained(self) -> None:
        class Hostile:
            @property
            def name(self) -> str:
                """Fail on the very first thing orchestration reads.

                Raises:
                    RuntimeError: Always.
                """
                msg = "no name for you"
                raise RuntimeError(msg)

            @property
            def capability(self) -> Capability:  # pragma: no cover
                msg = "no capability either"
                raise RuntimeError(msg)

            def fetch(self, pkg: PackageInfo) -> ProviderResult:  # pragma: no cover
                msg = f"should not be consulted for {pkg.name}"
                raise AssertionError(msg)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[Hostile(), downloads]
        )
        # Reading the provider's own identity is inside the guard, and the
        # recovery path must not re-trip the fault it is reporting.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "unidentified provider"
        assert failure.field is None
        assert "RuntimeError: no name for you" in failure.reason

    def test_a_bare_key_error_from_a_provider_is_contained(self) -> None:
        class BareKeyError:
            name = "bare"
            capability: Capability = "download_count"

            def fetch(self, pkg: PackageInfo) -> ProviderResult:
                """Raise an argument-less KeyError, as an adapter bug might.

                Raises:
                    KeyError: Always, with no arguments.
                """
                assert pkg.name
                raise KeyError

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[BareKeyError(), downloads]
        )
        # The recovery path must not assume the exception carries arguments,
        # and must not mistake a provider's own lookup bug for a bad
        # capability declaration.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "bare"
        assert failure.reason == "provider raised KeyError: "
        assert failure.field == "result.download_count"

    def test_a_provider_returning_a_non_result_is_contained(self) -> None:
        class Malformed:
            name = "malformed"
            capability: Capability = "download_count"

            def fetch(self, pkg: PackageInfo) -> ProviderResult:
                """Return nothing at all, as a broken provider might.

                Returns:
                    Not a result, despite the annotation.
                """
                assert pkg.name
                # Deliberately lies about its return type, as a broken
                # third-party provider would.
                return cast("ProviderResult", None)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[Malformed(), downloads]
        )
        # Inspecting the result must not crash before containment applies.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        assert pkg.enrichment_failures[0].source == "malformed"

    def test_a_provider_with_an_unhashable_name_is_contained(self) -> None:
        class UnhashableName:
            name = cast("str", ["not", "a", "name"])
            capability: Capability = "download_count"

            def fetch(self, pkg: PackageInfo) -> ProviderResult:  # pragma: no cover
                msg = f"should not be consulted for {pkg.name}"
                raise AssertionError(msg)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[UnhashableName(), downloads]
        )
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "unidentified provider"
        assert "not str" in failure.reason

    def test_a_provider_returning_an_unhashable_capability_is_contained(self) -> None:
        class Shapeshifter:
            name = "shapeshifter"
            capability = cast("Capability", ["not", "a", "capability"])

            def fetch(self, pkg: PackageInfo) -> ProviderResult:  # pragma: no cover
                msg = f"should not be consulted for {pkg.name}"
                raise AssertionError(msg)

        downloads = _downloads()
        pkg = enrich(
            _pkg(), no_osv=True, no_stats=False, providers=[Shapeshifter(), downloads]
        )
        # An unhashable capability must not escape containment a second time
        # when provenance later looks up its field.
        assert downloads.calls == ["requests"]
        assert pkg.download_count == 100
        failure = pkg.enrichment_failures[0]
        assert failure.source == "shapeshifter"
        assert "unhashable" in failure.reason
        assert failure.field is None

    def test_unavailable_provider_is_not_a_failure(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _dependents(state="unavailable", evidence=None, reason="no API key")
            ],
        )
        assert pkg.enrichment_failures == []
        assert pkg.enrichment_sources[0].state == "unavailable"
        assert pkg.enrichment_sources[0].reason == "no API key"

    def test_provider_warnings_are_propagated(self) -> None:
        warning = ProviderWarning(
            source="pypistats", code="rate_limited", message="throttled to 1 req/s"
        )
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[_downloads(warnings=[warning])],
        )
        assert pkg.provider_warnings == [warning]


class TestMergeConflicts:
    """Two providers answering one field must disagree explicitly."""

    def test_first_provider_wins_and_conflict_is_recorded(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        # Deterministic by provider order, not by whichever finished last.
        assert pkg.download_count == 100
        assert pkg.enrichment_conflicts == [
            ProviderConflict(
                field="result.download_count", kept="pypistats", discarded="deps.dev"
            )
        ]

    def test_agreeing_providers_produce_no_conflict(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(100, name="deps.dev"),
            ],
        )
        assert pkg.download_count == 100
        assert pkg.enrichment_conflicts == []

    def test_both_sources_keep_their_provenance(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        # The losing provider is still reported as a consulted source.
        assert [source.name for source in pkg.enrichment_sources] == [
            "pypistats",
            "deps.dev",
        ]

    def test_vulnerabilities_union_instead_of_conflicting(self) -> None:
        pkg = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[
                _osv(name="osv", evidence=VulnerabilityEvidence([_vuln("GHSA-1")])),
                _osv(name="ghsa", evidence=VulnerabilityEvidence([_vuln("GHSA-2")])),
            ],
        )
        assert sorted(v.id for v in pkg.vulnerabilities) == ["GHSA-1", "GHSA-2"]
        assert pkg.enrichment_conflicts == []


class TestComposedPasses:
    """Enriching an already-enriched package must not forget the first pass."""

    def test_a_later_pass_cannot_silently_overwrite_a_scalar(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[_downloads(100, name="pypistats")],
        )
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(999, name="deps.dev")],
        )
        # First-writer-wins holds across passes, not just within one.
        assert second.download_count == 100
        assert second.enrichment_conflicts == [
            ProviderConflict(
                field="result.download_count", kept="pypistats", discarded="deps.dev"
            )
        ]

    def test_a_later_pass_keeps_earlier_conflicts(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        assert len(first.enrichment_conflicts) == 1
        second = enrich(first, no_osv=False, no_stats=True, providers=[_osv()])
        # The earlier disagreement must survive a later pass that has none.
        assert second.enrichment_conflicts == first.enrichment_conflicts

    def test_an_agreeing_later_pass_produces_no_conflict(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[_downloads(100, name="pypistats")],
        )
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(100, name="deps.dev")],
        )
        assert second.download_count == 100
        assert second.enrichment_conflicts == []

    def test_a_later_conflict_names_the_original_owner(self) -> None:
        # Pass 1 consulted two sources; pypistats won. A third source
        # conflicting later must be told it lost to pypistats, not to the
        # last source that merely reported the same field.
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(555, name="third-party")],
        )
        assert second.download_count == 100
        assert second.enrichment_conflicts[-1] == ProviderConflict(
            field="result.download_count", kept="pypistats", discarded="third-party"
        )

    def test_reconsulting_a_discarded_source_does_not_self_conflict(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(999, name="deps.dev")],
        )
        # Never "kept deps.dev, discarded deps.dev".
        conflict = second.enrichment_conflicts[-1]
        assert conflict.kept == "pypistats"
        assert conflict.discarded == "deps.dev"

    def test_a_reconsulted_source_that_now_agrees_clears_the_conflict(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[
                _downloads(100, name="pypistats"),
                _downloads(999, name="deps.dev"),
            ],
        )
        assert len(first.enrichment_conflicts) == 1
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(100, name="deps.dev")],
        )
        assert second.enrichment_conflicts == []

    def test_a_successful_retry_clears_the_stale_failure(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[_osv(state="failed", evidence=None, reason="HTTP 500")],
        )
        assert first.vulnerabilities_unknown
        second = enrich(first, no_osv=False, no_stats=True, providers=[_osv()])
        # The obsolete failure must not linger once the retry succeeds.
        assert second.enrichment_failures == []
        assert second.vulnerabilities_unknown is False
        assert [v.id for v in second.vulnerabilities] == ["GHSA-1"]

    def test_a_confirmed_empty_retry_also_clears_the_stale_failure(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[_osv(state="failed", evidence=None, reason="HTTP 500")],
        )
        assert first.vulnerabilities_unknown
        second = enrich(
            first,
            no_osv=False,
            no_stats=True,
            providers=[_osv(state="empty", evidence=VulnerabilityEvidence([]))],
        )
        # "Queried, and there are none" answers the question as definitively
        # as a hit, so the count must read 0 rather than "unknown".
        assert second.enrichment_failures == []
        assert second.vulnerabilities_unknown is False
        assert second.vulnerabilities == []

    def test_a_skipped_retry_leaves_the_stale_failure_in_place(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=False,
            no_stats=True,
            providers=[_osv(state="failed", evidence=None, reason="HTTP 500")],
        )
        second = enrich(first, no_osv=True, no_stats=True, providers=[_osv()])
        # Nothing was looked up, so nothing is resolved.
        assert [failure.source for failure in second.enrichment_failures] == ["osv"]
        assert second.vulnerabilities_unknown

    def test_a_success_does_not_clear_an_unrelated_failing_field(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=False,
            no_stats=False,
            providers=[
                _osv(state="failed", evidence=None, reason="HTTP 500"),
                _downloads(state="failed", evidence=None, reason="HTTP 503"),
            ],
        )
        assert len(first.enrichment_failures) == 2
        # Only the download source recovers; the vulnerability failure must
        # remain since it is a different (source, field) pair.
        second = enrich(first, no_osv=False, no_stats=False, providers=[_downloads()])
        assert [failure.source for failure in second.enrichment_failures] == ["osv"]
        assert second.vulnerabilities_unknown

    def test_the_owning_provider_may_refresh_its_own_count(self) -> None:
        first = enrich(
            _pkg(),
            no_osv=True,
            no_stats=False,
            providers=[_downloads(100, name="pypistats")],
        )
        second = enrich(
            first,
            no_osv=True,
            no_stats=False,
            providers=[_downloads(101, name="pypistats")],
        )
        # A monthly download count legitimately moves, and a source cannot
        # disagree with itself.
        assert second.download_count == 101
        assert second.enrichment_conflicts == []


class TestConcurrentConsultation:
    def test_providers_are_consulted_at_the_same_time(self) -> None:
        # Three unrelated services, no dependency between them: waiting for
        # each in turn was roughly 44% of a package's enrichment latency.
        started = threading.Barrier(3, timeout=5)

        def blocking(name: str, capability: Capability) -> FakeProvider:
            def fetch(pkg: PackageInfo) -> ProviderResult:
                _ = started.wait()
                return ProviderResult(
                    provider=name,
                    capability=capability,
                    state="empty",
                    subject=pkg.name,
                    retrieved_at=utc_now(),
                )

            return FakeProvider(name=name, capability=capability, fetch_impl=fetch)

        providers = [
            blocking("osv", "vulnerabilities"),
            blocking("pypistats", "download_count"),
            blocking("libraries.io", "dependent_count"),
        ]

        # The barrier can only clear if all three are in flight at once.
        result = enrich(_pkg(), no_osv=False, no_stats=False, providers=providers)

        assert [source.name for source in result.enrichment_sources] == [
            "osv",
            "pypistats",
            "libraries.io",
        ]

    def test_the_first_provider_still_wins_a_conflict(self) -> None:
        # Merge order is consultation order, so if a slow provider could be
        # overtaken by a fast one the conflict resolution would become a race.
        def slow_winner(pkg: PackageInfo) -> ProviderResult:
            time.sleep(0.05)
            return ProviderResult(
                provider="slow",
                capability="download_count",
                state="success",
                subject=pkg.name,
                retrieved_at=utc_now(),
                evidence=CountEvidence(111),
            )

        def fast_loser(pkg: PackageInfo) -> ProviderResult:
            return ProviderResult(
                provider="fast",
                capability="download_count",
                state="success",
                subject=pkg.name,
                retrieved_at=utc_now(),
                evidence=CountEvidence(222),
            )

        providers = [
            FakeProvider(
                name="slow", capability="download_count", fetch_impl=slow_winner
            ),
            FakeProvider(
                name="fast", capability="download_count", fetch_impl=fast_loser
            ),
        ]

        result = enrich(_pkg(), no_osv=False, no_stats=False, providers=providers)

        assert result.download_count == 111
        assert result.enrichment_conflicts[0].kept == "slow"
        assert result.enrichment_conflicts[0].discarded == "fast"
