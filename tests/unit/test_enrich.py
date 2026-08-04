"""Unit tests for shared OSV + stats enrichment (core layer mocked)."""

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from peta.core.enrich import enrich
from peta.core.models import PackageInfo, Vulnerability

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(name="requests", version="2.31.0", source="local")
    return replace(base, **over)


class TestEnrich:
    @patch("peta.core.enrich.osv.get_vulnerabilities")
    def test_merges_osv_vulnerabilities(self, mo: MagicMock) -> None:
        mo.return_value = [
            Vulnerability(id="GHSA-1", aliases=[], summary="s", fixed_in=["1.1"])
        ]
        pkg = enrich(_pkg(), no_osv=False, no_stats=True)
        assert pkg.vulnerabilities[0].id == "GHSA-1"
        mo.assert_called_once_with("requests", "2.31.0")

    @patch("peta.core.enrich.osv.get_vulnerabilities")
    def test_no_osv_skips_lookup(self, mo: MagicMock) -> None:
        pkg = enrich(_pkg(), no_osv=True, no_stats=True)
        mo.assert_not_called()
        assert pkg.vulnerabilities == []

    @patch("peta.core.enrich.stats.libraries_io_api_key")
    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    def test_sets_stats_counts(
        self, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        mdl.return_value = 100
        mdep.return_value = 5
        mkey.return_value = "secret"
        pkg = enrich(_pkg(), no_osv=True, no_stats=False)
        assert pkg.download_count == 100
        assert pkg.dependent_count == 5
        mdep.assert_called_once_with("requests", api_key="secret")

    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    def test_no_stats_skips_lookup(self, mdl: MagicMock, mdep: MagicMock) -> None:
        pkg = enrich(_pkg(), no_osv=True, no_stats=True)
        mdl.assert_not_called()
        mdep.assert_not_called()
        assert pkg.download_count is None
        assert pkg.dependent_count is None

    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    @patch("peta.core.enrich.osv.get_vulnerabilities")
    def test_best_effort_never_raises(
        self, mo: MagicMock, mdl: MagicMock, mdep: MagicMock
    ) -> None:
        # osv/stats modules already swallow network errors internally and
        # return empty/None results; enrich itself adds no additional error
        # handling and must not raise.
        mo.return_value = []
        mdl.return_value = None
        mdep.return_value = None
        pkg = enrich(_pkg(), no_osv=False, no_stats=False)
        assert pkg.name == "requests"
