"""Unit tests for JSON formatters."""

import json
from dataclasses import replace

import pytest

from peta.cli.output.json import (
    format_compare,
    format_dep_tree,
    format_files,
    format_info,
    format_versions,
    format_why,
)
from peta.core.models import (
    DependencyNode,
    EnrichmentFailure,
    PackageInfo,
    Vulnerability,
)

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="requests",
        version="2.31.0",
        source="local",
        dependencies=["urllib3"],
        files=None,
        vulnerabilities=[],
    )
    return replace(base, **over)


def test_info_basic() -> None:
    data = json.loads(format_info(_pkg()))
    assert data["name"] == "requests"
    assert data["source"] == "local"
    assert "urllib3" in data["dependencies"]
    # Full metadata surface is serialized.
    for key in ("author_email", "maintainer", "classifiers", "keywords"):
        assert key in data


def test_info_identifies_license_expression() -> None:
    data = json.loads(format_info(_pkg(license="MIT", license_source="expression")))
    assert data["license"] == "MIT"
    assert data["license_source"] == "expression"


def test_info_vulns() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["1.1"])
    data = json.loads(format_info(_pkg(vulnerabilities=[v])))
    assert data["vulnerabilities"][0]["id"] == "PYSEC-1"


def test_info_stats() -> None:
    data = json.loads(format_info(_pkg(download_count=12345, dependent_count=42)))
    assert data["download_count"] == 12345
    assert data["dependent_count"] == 42


def test_info_stats_default_none() -> None:
    data = json.loads(format_info(_pkg()))
    assert data["download_count"] is None
    assert data["dependent_count"] is None


def test_info_exposes_enrichment_failures() -> None:
    failure = EnrichmentFailure(source="osv", reason="HTTP 503")
    data = json.loads(format_info(_pkg(enrichment_failures=[failure])))
    assert data["enrichment_failures"] == [{"source": "osv", "reason": "HTTP 503"}]


def test_compare() -> None:
    b = _pkg(name="httpx", version="0.27.0", dependencies=["httpcore"])
    data = json.loads(format_compare(_pkg(), b))
    assert len(data["packages"]) == 2
    assert data["packages"][0]["name"] == "requests"
    assert data["packages"][1]["name"] == "httpx"


def test_dep_tree() -> None:
    child = DependencyNode(
        name="urllib3", version_spec=">=1.21.1", installed_version="2.0"
    )
    root = DependencyNode(
        name="requests", version_spec="", installed_version="2.31.0", children=[child]
    )
    data = json.loads(format_dep_tree(root))
    assert data["name"] == "requests"
    assert data["children"][0]["name"] == "urllib3"
    assert data["children"][0]["installed_version"] == "2.0"
    assert data["circular"] is False


def test_dep_tree_circular() -> None:
    node = DependencyNode(name="a", version_spec="", circular=True)
    data = json.loads(format_dep_tree(node))
    assert data["circular"] is True
    assert data["children"] == []


def test_why() -> None:
    data = json.loads(format_why("certifi", [["flask", "requests", "certifi"]]))
    assert data["target"] == "certifi"
    assert data["paths"] == [["flask", "requests", "certifi"]]


def test_why_empty() -> None:
    data = json.loads(format_why("nope", []))
    assert data["paths"] == []


def test_files_none_and_some() -> None:
    assert json.loads(format_files(_pkg(files=None)))["files"] == []
    got = json.loads(format_files(_pkg(files=["a.py"])))["files"]
    assert got == ["a.py"]


def test_versions() -> None:
    data = json.loads(
        format_versions(
            "requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        )
    )
    assert data["name"] == "requests"
    assert len(data["versions"]) == 1
