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
    DependencyResolutionFailure,
    EnrichmentFailure,
    PackageInfo,
    ProviderConflict,
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
    data = json.loads(format_info(_pkg()))["result"]
    assert data["name"] == "requests"
    assert data["source"] == "local"
    assert "urllib3" in data["dependencies"]
    # Full metadata surface is serialized.
    for key in ("author_email", "maintainer", "classifiers", "keywords"):
        assert key in data


def test_info_identifies_license_expression() -> None:
    data = json.loads(format_info(_pkg(license="MIT", license_source="expression")))[
        "result"
    ]
    assert data["license"] == "MIT"
    assert data["license_source"] == "expression"


def test_info_vulns() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["1.1"])
    data = json.loads(format_info(_pkg(vulnerabilities=[v])))["result"]
    assert data["vulnerabilities"][0]["id"] == "PYSEC-1"


def test_info_stats() -> None:
    data = json.loads(format_info(_pkg(download_count=12345, dependent_count=42)))[
        "result"
    ]
    assert data["download_count"] == 12345
    assert data["dependent_count"] == 42


def test_info_stats_default_none() -> None:
    data = json.loads(format_info(_pkg()))["result"]
    assert data["download_count"] is None
    assert data["dependent_count"] is None


def test_info_exposes_enrichment_failures() -> None:
    failure = EnrichmentFailure(source="osv", reason="HTTP 503")
    data = json.loads(format_info(_pkg(enrichment_failures=[failure])))
    assert data["warnings"] == [
        {"code": "enrichment_failed", "message": "HTTP 503", "source": "osv"}
    ]


def test_compare() -> None:
    b = _pkg(name="httpx", version="0.27.0", dependencies=["httpcore"])
    data = json.loads(format_compare(_pkg(), b))["result"]
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
    data = json.loads(format_dep_tree(root))["result"]
    assert data["name"] == "requests"
    assert data["children"][0]["name"] == "urllib3"
    assert data["children"][0]["installed_version"] == "2.0"
    assert data["circular"] is False


def test_dep_tree_circular() -> None:
    node = DependencyNode(name="a", version_spec="", circular=True)
    data = json.loads(format_dep_tree(node))["result"]
    assert data["circular"] is True
    assert data["children"] == []


def test_dep_tree_reports_transitive_resolution_failure_as_partial() -> None:
    leaf = DependencyNode(
        name="unreachable",
        version_spec=">=1",
        resolution_failure=DependencyResolutionFailure(
            source="pypi",
            state="failed",
            reason="connection reset",
            retrieved_at="2026-09-04T12:00:00Z",
        ),
    )
    root = DependencyNode(
        name="requests", version_spec="", source="local", children=[leaf]
    )
    data = json.loads(format_dep_tree(root, generated_at="2026-09-04T12:00:01Z"))
    assert data["status"] == "partial"
    assert data["result"]["children"][0]["resolution"]["state"] == "failed"
    assert data["warnings"][0]["code"] == "dependency_resolution_failed"
    assert data["sources"][1]["fields"] == ["result.children[0]"]


def test_why() -> None:
    data = json.loads(format_why("certifi", [["flask", "requests", "certifi"]]))[
        "result"
    ]
    assert data["target"] == "certifi"
    assert data["paths"] == [["flask", "requests", "certifi"]]


def test_why_sources_reference_emitted_path_elements() -> None:
    certifi = DependencyNode(name="certifi", version_spec="", source="remote")
    requests = DependencyNode(
        name="requests", version_spec="", source="local", children=[certifi]
    )
    tree = DependencyNode(
        name="flask", version_spec="", source="local", children=[requests]
    )
    data = json.loads(
        format_why(
            "certifi",
            [["flask", "requests", "certifi"]],
            tree=tree,
            generated_at="2026-09-04T12:00:00Z",
        )
    )
    assert [source["fields"] for source in data["sources"]] == [
        ["result.paths[0][0]"],
        ["result.paths[0][1]"],
        ["result.paths[0][2]"],
    ]


def test_remote_packages_are_attributed_to_the_pypi_provider() -> None:
    data = json.loads(format_info(_pkg(source="remote")))
    # ``result.source`` keeps its legacy value; provenance names one provider.
    assert data["result"]["source"] == "remote"
    assert data["sources"][0]["name"] == "pypi"


def test_why_off_path_failures_carry_no_result_field() -> None:
    failure = DependencyResolutionFailure(
        source="pypi",
        state="failed",
        reason="connection reset",
        retrieved_at="2026-09-04T12:00:00Z",
    )
    target = DependencyNode(name="certifi", version_spec="", source="local")
    broken = DependencyNode(
        name="unreachable", version_spec=">=1", resolution_failure=failure
    )
    tree = DependencyNode(
        name="flask", version_spec="", source="local", children=[target, broken]
    )
    data = json.loads(
        format_why(
            "certifi",
            [["flask", "certifi"]],
            tree=tree,
            generated_at="2026-09-04T12:00:01Z",
        )
    )
    off_path = next(s for s in data["sources"] if s["target"] == "unreachable")
    # The failure is off the returned paths, so no result path can identify it.
    assert off_path["fields"] == []
    assert off_path["state"] == "failed"
    assert data["status"] == "partial"


def test_why_empty() -> None:
    data = json.loads(format_why("nope", []))["result"]
    assert data["paths"] == []


def test_files_none_and_some() -> None:
    assert json.loads(format_files(_pkg(files=None)))["result"]["files"] == []
    got = json.loads(format_files(_pkg(files=["a.py"])))["result"]["files"]
    assert got == ["a.py"]


def test_versions() -> None:
    data = json.loads(
        format_versions(
            "requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        )
    )["result"]
    assert data["name"] == "requests"
    assert len(data["versions"]) == 1


def test_provider_conflict_is_reported_as_a_warning() -> None:
    data = json.loads(
        format_info(
            _pkg(
                enrichment_conflicts=[
                    ProviderConflict(
                        field="result.download_count",
                        kept="pypistats",
                        discarded="deps.dev",
                    )
                ]
            )
        )
    )
    assert data["status"] == "partial"
    warning = data["warnings"][0]
    assert warning["code"] == "provider_conflict"
    assert warning["source"] == "pypistats"
    # Both sides of the disagreement stay named in the message.
    assert "deps.dev" in warning["message"]
