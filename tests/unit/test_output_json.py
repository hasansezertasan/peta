"""Unit tests for JSON formatters."""

import json
from dataclasses import replace

import pytest

from peta.core.models import PackageInfo, Vulnerability
from peta.output.json import (
    format_compare,
    format_deps,
    format_files,
    format_info,
    format_versions,
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


def test_compare() -> None:
    b = _pkg(name="httpx", version="0.27.0", dependencies=["httpcore"])
    data = json.loads(format_compare(_pkg(), b))
    assert len(data["packages"]) == 2
    assert data["packages"][0]["name"] == "requests"
    assert data["packages"][1]["name"] == "httpx"


def test_deps() -> None:
    data = json.loads(format_deps(_pkg()))
    assert isinstance(data["dependencies"], list)


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
