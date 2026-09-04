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
from peta.core.models import DependencyNode, PackageInfo

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


def test_compare() -> None:
    output = format_compare(_pkg(), _pkg(name="httpx", version="0.27.0"))
    assert "# Package comparison" in output
    assert "| Version | 2.31.0 | 0.27.0 |" in output


def test_dependency_tree() -> None:
    child = DependencyNode(name="urllib3", version_spec=">=2", circular=True)
    root = DependencyNode(name="requests", version_spec="", children=[child])
    output = format_dep_tree(root)
    assert "- `requests`" in output
    assert "  - `urllib3 >=2` _(circular)_" in output


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
