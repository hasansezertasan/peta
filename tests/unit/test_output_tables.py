"""Unit tests for Rich renderers."""

from dataclasses import replace

import pytest

from peta.core.models import PackageInfo, Vulnerability
from peta.output.tables import render_deps, render_files, render_info, render_versions

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


def test_render_deps() -> None:
    assert "urllib3" in render_deps(_pkg(), color=False)


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
