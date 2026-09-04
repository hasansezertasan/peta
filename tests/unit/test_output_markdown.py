"""Unit tests for Markdown output formatters."""

from __future__ import annotations

from dataclasses import replace

import pytest

from peta.cli.output.markdown import (
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
        summary="HTTP | client\nfor humans",
        dependencies=["urllib3"],
        files=["requests/__init__.py"],
    )
    return replace(base, **over)


def test_info() -> None:
    output = format_info(_pkg())
    assert output.startswith("# requests 2.31.0")
    assert "HTTP \\| client for humans" in output
    assert "urllib3" in output
    assert "| License | — |" in output


def test_info_preserves_security_findings_and_warnings() -> None:
    output = format_info(
        _pkg(
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-test",
                    aliases=[],
                    summary="unsafe | release",
                    fixed_in=["2.32.0"],
                    severity="HIGH",
                )
            ],
            enrichment_failures=[EnrichmentFailure(source="osv", reason="HTTP 503")],
        )
    )
    assert "## Vulnerabilities" in output
    assert "`GHSA-test` (HIGH): unsafe \\| release" in output
    assert "## Enrichment warnings\n\n- **osv:** HTTP 503" in output


def test_compare() -> None:
    output = format_compare(_pkg(), _pkg(name="httpx", version="0.27.0"))
    assert "# Package comparison" in output
    assert "| Version | 2.31.0 | 0.27.0 |" in output


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
    assert "| Vulnerabilities | 1 | unknown |" in output
    assert "- `httpx` — **osv:** HTTP 503" in output


def test_dependency_tree() -> None:
    child = DependencyNode(name="urllib3", version_spec=">=2", circular=True)
    root = DependencyNode(name="requests", version_spec="", children=[child])
    output = format_dep_tree(root)
    assert "- `requests`" in output
    assert "  - `urllib3 >=2` _(circular)_" in output


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
        name="requests", version_spec="", children=[resolved, unresolved]
    )
    output = format_dep_tree(root)
    assert "  - `urllib3 >=1.21.1` _(installed 2.5.0)_" in output
    assert "  - `ghost >=1` _(unresolved: Package 'ghost' not found.)_" in output


def test_why() -> None:
    output = format_why("urllib3", [["requests", "urllib3"]])
    assert "# Why urllib3?" in output
    assert "`requests` → `urllib3`" in output


def test_files() -> None:
    output = format_files(_pkg())
    assert "# Files for requests 2.31.0" in output
    assert "- `requests/__init__.py`" in output


def test_versions() -> None:
    output = format_versions(
        "requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}]
    )
    assert "# Versions for requests" in output
    assert "| 2.31.0 | 2023-05-22 |" in output


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
    assert "## Enrichment warnings" in output
    assert (
        "- **result.download_count:** kept pypistats, "
        "discarded conflicting deps.dev" in output
    )
