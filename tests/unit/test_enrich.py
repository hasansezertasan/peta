"""Unit tests for enrichment orchestration over in-memory fake providers.

These exercise orchestration only: no HTTP module is patched, so a provider's
transport is irrelevant here and covered by its own client tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from peta.core.enrich import enrich
from peta.core.models import (
    VULNERABILITY_FIELD,
    EnrichmentFailure,
    PackageInfo,
    ProviderConflict,
    Vulnerability,
)
from peta.core.providers import (
    Capability,
    CountEvidence,
    Evidence,
    ProviderGroup,
    ProviderResult,
    VulnerabilityEvidence,
)

if TYPE_CHECKING:
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
    group: ProviderGroup
    state: SourceState = "success"
    evidence: Evidence | None = None
    reason: str | None = None
    calls: list[str] = field(default_factory=list)

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Record the call and return the canned result.

        Returns:
            The configured provider result.
        """
        self.calls.append(pkg.name)
        return ProviderResult(
            provider=self.name,
            capability=self.capability,
            state=self.state,
            subject=pkg.name,
            retrieved_at="2026-09-04T12:00:00Z",
            evidence=self.evidence,
            reason=self.reason,
        )


def _vuln(identifier: str) -> Vulnerability:
    return Vulnerability(id=identifier, aliases=[], summary="s", fixed_in=["1.1"])


def _osv(**over: object) -> FakeProvider:
    base = FakeProvider(
        name="osv",
        capability="vulnerabilities",
        group="vulnerabilities",
        evidence=VulnerabilityEvidence([_vuln("GHSA-1")]),
    )
    return replace(base, **over)


def _downloads(count: int = 100, **over: object) -> FakeProvider:
    base = FakeProvider(
        name="pypistats",
        capability="download_count",
        group="stats",
        evidence=CountEvidence(count),
    )
    return replace(base, **over)


def _dependents(count: int = 5, **over: object) -> FakeProvider:
    base = FakeProvider(
        name="libraries.io",
        capability="dependent_count",
        group="stats",
        evidence=CountEvidence(count),
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
