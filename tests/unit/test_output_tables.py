"""Unit tests for Rich renderers."""

from dataclasses import replace

import pytest

from peta.cli.output.tables import (
    render_compare,
    render_dep_tree,
    render_files,
    render_info,
    render_versions,
    render_why,
)
from peta.core.models import DependencyNode, PackageInfo, Vulnerability

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="requests",
        version="2.31.0",
        source="local",
        summary="Python HTTP for Humans.",
        homepage="https://x",
        project_urls={"Repo": "https://github.com/psf/requests"},
        dependencies=["urllib3", "idna"],
        files=None,
        vulnerabilities=[],
    )
    return replace(base, **over)


def test_render_info_string() -> None:
    out = render_info(_pkg(), color=False)
    assert isinstance(out, str)
    assert "requests" in out
    assert "2.31.0" in out


def test_render_info_identifies_license_expression() -> None:
    out = render_info(_pkg(license="MIT", license_source="expression"), color=False)
    assert "License (SPDX)" in out
    assert "MIT" in out


def test_render_info_color() -> None:
    out = render_info(_pkg(), color=True)
    assert "\x1b" in out


def test_render_info_vulns() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="bad", fixed_in=["2.32.0"])
    assert "PYSEC-1" in render_info(_pkg(vulnerabilities=[v]), color=False)


def test_render_info_no_dependencies() -> None:
    out = render_info(_pkg(dependencies=[]), color=False)
    assert "requests" in out
    assert "Dependencies" not in out


def test_render_info_stats() -> None:
    out = render_info(_pkg(download_count=1234567, dependent_count=42), color=False)
    assert "1,234,567" in out
    assert "42" in out


def test_render_info_no_stats() -> None:
    out = render_info(_pkg(), color=False)
    assert "Downloads" not in out
    assert "Dependents" not in out


def test_render_compare() -> None:
    b = _pkg(name="httpx", version="0.27.0", dependencies=["httpcore"])
    out = render_compare(_pkg(), b, color=False)
    assert "requests" in out
    assert "httpx" in out
    assert "2.31.0" in out
    assert "0.27.0" in out


def test_render_compare_identifies_license_expression() -> None:
    a = _pkg(license="MIT", license_source="expression")
    b = _pkg(name="httpx", license="BSD", license_source="legacy")
    out = render_compare(a, b, color=False)
    assert "MIT (SPDX)" in out
    assert "BSD" in out


def test_render_compare_missing_values_show_dash() -> None:
    a = _pkg(
        summary=None,
        author=None,
        license=None,
        python_requires=None,
        download_count=None,
        dependent_count=None,
    )
    b = _pkg(name="httpx", version="0.27.0")
    out = render_compare(a, b, color=False)
    assert "-" in out


def test_render_compare_empty_license_shows_dash() -> None:
    a = _pkg(license="", license_source="legacy")
    b = _pkg(name="httpx", license="", license_source="expression")
    out = render_compare(a, b, color=False)
    license_row = next(line for line in out.splitlines() if "License" in line)
    assert license_row.count("-") == 2


def test_render_compare_counts() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="bad", fixed_in=["1.0"])
    a = _pkg(
        dependencies=["urllib3"],
        vulnerabilities=[v],
        download_count=1234567,
        dependent_count=42,
    )
    b = _pkg(name="httpx", version="0.27.0", dependencies=[])
    out = render_compare(a, b, color=False)
    assert "1,234,567" in out
    assert "42" in out


def test_render_dep_tree() -> None:
    child = DependencyNode(
        name="urllib3", version_spec=">=1.21.1", installed_version="2.0"
    )
    root = DependencyNode(
        name="requests", version_spec="", installed_version="2.31.0", children=[child]
    )
    out = render_dep_tree(root, color=False)
    assert "requests" in out
    assert "urllib3" in out
    assert "installed 2.0" in out


def test_render_dep_tree_unresolved_child_no_installed_version() -> None:
    child = DependencyNode(name="missing", version_spec=">=1.0")
    root = DependencyNode(name="a", version_spec="", children=[child])
    out = render_dep_tree(root, color=False)
    assert "missing" in out
    assert "installed" not in out


def test_render_dep_tree_circular() -> None:
    circular_child = DependencyNode(name="a", version_spec="", circular=True)
    root = DependencyNode(name="a", version_spec="", children=[circular_child])
    out = render_dep_tree(root, color=False)
    assert "(circular)" in out


def test_render_why() -> None:
    out = render_why("certifi", [["flask", "requests", "certifi"]], color=False)
    assert "flask" in out
    assert "→" in out


def test_render_why_empty() -> None:
    out = render_why("nope", [], color=False)
    assert "not a dependency" in out


def test_render_files_some_and_none() -> None:
    assert "__init__.py" in render_files(
        _pkg(files=["requests/__init__.py"]), color=False
    )
    assert "no file" in render_files(_pkg(files=None), color=False).lower()


def test_render_versions() -> None:
    out = render_versions(
        "requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}], color=False
    )
    assert "2.31.0" in out
