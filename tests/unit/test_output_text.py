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
from peta.core.models import DependencyNode, PackageInfo

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


def test_compare() -> None:
    output = format_compare(_pkg(), _pkg(name="httpx", version="0.27.0"))
    assert output.startswith("Field\trequests\thttpx")
    assert "Version\t2.31.0\t0.27.0" in output


def test_dependency_tree() -> None:
    child = DependencyNode(name="urllib3", version_spec=">=2", circular=True)
    root = DependencyNode(name="requests", version_spec="", children=[child])
    assert format_dep_tree(root) == "requests\n  urllib3 >=2 (circular)"


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
