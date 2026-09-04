"""Unit tests for plain-text output formatters."""

from __future__ import annotations

from dataclasses import replace

import pytest

from peta.cli.output.text import (
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
        summary="HTTP client\nfor humans",
        dependencies=["urllib3"],
        files=["requests/__init__.py"],
    )
    return replace(base, **over)


def test_info() -> None:
    output = format_info(_pkg())
    assert output.startswith("Name: requests\nVersion: 2.31.0")
    assert "Summary: HTTP client for humans" in output
    assert "License: -" in output


def test_info_preserves_security_findings_and_warnings() -> None:
    output = format_info(
        _pkg(
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-test",
                    aliases=[],
                    summary="unsafe release",
                    fixed_in=["2.32.0"],
                    severity="HIGH",
                )
            ],
            enrichment_failures=[EnrichmentFailure(source="osv", reason="HTTP 503")],
        )
    )
    assert "Vulnerabilities:\n- GHSA-test [HIGH]: unsafe release" in output
    assert "Enrichment warnings:\n- osv: HTTP 503" in output


def test_compare() -> None:
    output = format_compare(_pkg(), _pkg(name="httpx", version="0.27.0"))
    assert output.startswith("Field\trequests\thttpx")
    assert "Version\t2.31.0\t0.27.0" in output


def test_compare_reports_security_state_for_both_packages() -> None:
    a = _pkg(
        vulnerabilities=[
            Vulnerability(
                id="GHSA-a", aliases=[], summary="bad", fixed_in=[], severity=None
            )
        ]
    )
    b = _pkg(
        name="httpx",
        version="0.27.0",
        enrichment_failures=[EnrichmentFailure(source="osv", reason="HTTP 503")],
    )
    output = format_compare(a, b)
    # An OSV failure must read as "unknown", never as a clean zero.
    assert "Vulnerabilities\t1\tunknown" in output
    assert "Enrichment warnings:\n- httpx: osv: HTTP 503" in output


def test_dependency_tree() -> None:
    child = DependencyNode(name="urllib3", version_spec=">=2", circular=True)
    root = DependencyNode(name="requests", version_spec="", children=[child])
    assert format_dep_tree(root) == "requests\n  urllib3 >=2 (circular)"


def test_dependency_tree_shows_resolved_and_unresolved_nodes() -> None:
    resolved = DependencyNode(
        name="urllib3", version_spec=">=1.21.1", installed_version="2.5.0"
    )
    unresolved = DependencyNode(
        name="ghost",
        version_spec=">=1",
        resolution_failure=DependencyResolutionFailure(
            source="pypi",
            state="empty",
            reason="Package 'ghost' not found.",
            retrieved_at="2026-09-04T12:00:00Z",
        ),
    )
    root = DependencyNode(
        name="requests",
        version_spec="",
        installed_version="2.31.0",
        children=[resolved, unresolved],
    )
    output = format_dep_tree(root)
    assert "  urllib3 >=1.21.1 (installed 2.5.0)" in output
    assert "  ghost >=1 (unresolved: Package 'ghost' not found.)" in output


def test_why() -> None:
    output = format_why("urllib3", [["requests", "urllib3"]])
    assert output == "Why urllib3?\nrequests -> urllib3"


def test_files() -> None:
    output = format_files(_pkg())
    assert output == "Files for requests 2.31.0\nrequests/__init__.py"


def test_versions() -> None:
    output = format_versions(
        "requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}]
    )
    assert output == "Versions for requests\nVersion\tUploaded\n2.31.0\t2023-05-22"


def test_info_reports_provider_conflicts_as_warnings() -> None:
    output = format_info(
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
    assert "Enrichment warnings:" in output
    assert (
        "- result.download_count: kept pypistats, discarded conflicting deps.dev"
        in output
    )
