"""Unit tests for vulnerability dedup/merge."""

import pytest

from peta.core.models import Vulnerability
from peta.core.vulns import merge_vulnerabilities

pytestmark = pytest.mark.unit


def test_no_overlap_keeps_both_in_order() -> None:
    a = Vulnerability(id="PYSEC-1", aliases=[], summary="a", fixed_in=["1.0"])
    b = Vulnerability(id="GHSA-2", aliases=[], summary="b", fixed_in=["2.0"])
    result = merge_vulnerabilities([a], [b])
    assert result == [a, b]


def test_dedups_by_same_id() -> None:
    a = Vulnerability(id="PYSEC-1", aliases=[], summary="a", fixed_in=["1.0"])
    b = Vulnerability(id="PYSEC-1", aliases=["CVE-1"], summary="a2", fixed_in=["1.1"])
    result = merge_vulnerabilities([a], [b])
    assert len(result) == 1
    assert result[0].aliases == ["CVE-1"]
    assert set(result[0].fixed_in) == {"1.0", "1.1"}


def test_dedups_by_overlapping_alias() -> None:
    a = Vulnerability(id="PYSEC-1", aliases=["CVE-1"], summary="a", fixed_in=[])
    b = Vulnerability(id="GHSA-2", aliases=["CVE-1"], summary="b", fixed_in=[])
    result = merge_vulnerabilities([a], [b])
    assert len(result) == 1


def test_prefers_severity_bearing_entry() -> None:
    a = Vulnerability(id="PYSEC-1", aliases=[], summary="a", fixed_in=[], severity=None)
    b = Vulnerability(
        id="PYSEC-1", aliases=[], summary="b", fixed_in=[], severity="HIGH"
    )
    result = merge_vulnerabilities([a], [b])
    assert result[0].severity == "HIGH"


def test_prefers_existing_severity_over_new_without() -> None:
    a = Vulnerability(
        id="PYSEC-1", aliases=[], summary="a", fixed_in=[], severity="HIGH"
    )
    b = Vulnerability(id="PYSEC-1", aliases=[], summary="b", fixed_in=[], severity=None)
    result = merge_vulnerabilities([a], [b])
    assert result[0].severity == "HIGH"


def test_unions_aliases_and_fixed_in() -> None:
    a = Vulnerability(id="PYSEC-1", aliases=["CVE-1"], summary="a", fixed_in=["1.0"])
    b = Vulnerability(id="PYSEC-1", aliases=["CVE-2"], summary="b", fixed_in=["1.1"])
    result = merge_vulnerabilities([a], [b])
    assert set(result[0].aliases) == {"CVE-1", "CVE-2"}
    assert set(result[0].fixed_in) == {"1.0", "1.1"}


def test_preserves_order_existing_then_new() -> None:
    a = Vulnerability(id="A", aliases=[], summary="", fixed_in=[])
    b = Vulnerability(id="B", aliases=[], summary="", fixed_in=[])
    c = Vulnerability(id="C", aliases=[], summary="", fixed_in=[])
    result = merge_vulnerabilities([a, b], [c])
    assert [v.id for v in result] == ["A", "B", "C"]


def test_empty_inputs() -> None:
    assert merge_vulnerabilities([], []) == []
