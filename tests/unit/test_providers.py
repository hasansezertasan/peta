"""Unit tests for the built-in enrichment provider adapters.

Each adapter is checked for the mapping it owns: client outcome to provider
state, evidence, and reason. The clients themselves are patched at their own
module boundary, never at the HTTP layer.
"""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from peta.core.models import PackageInfo, Vulnerability
from peta.core.providers import (
    DEFAULT_PROVIDERS,
    CountEvidence,
    LibrariesIoProvider,
    OsvProvider,
    PypiStatsProvider,
    VulnerabilityEvidence,
)
from peta.core.validation import EnrichmentError

pytestmark = pytest.mark.unit


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
    @patch("peta.core.providers.builtin.stats.get_download_count", return_value=1234)
    def test_success_carries_count_evidence(self, m: MagicMock) -> None:
        result = PypiStatsProvider().fetch(_pkg())
        assert result.state == "success"
        assert result.evidence == CountEvidence(1234)
        assert result.field == "result.download_count"
        m.assert_called_once_with("requests")

    @patch("peta.core.providers.builtin.stats.get_download_count", return_value=None)
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

    @patch("peta.core.providers.builtin.stats.get_dependent_count", return_value=42)
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
    groups = {provider.name: provider.group for provider in DEFAULT_PROVIDERS}
    assert groups == {
        "osv": "vulnerabilities",
        "pypistats": "stats",
        "libraries.io": "stats",
    }
