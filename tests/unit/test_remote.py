"""Unit tests for the PyPI remote fetcher (httpx mocked)."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.models import PackageInfo
from peta.core.remote import NetworkError, PackageNotFoundError, get_package

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


_INFO = {
    "name": "requests",
    "version": "2.31.0",
    "summary": "Python HTTP for Humans.",
    "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org",
    "maintainer": None,
    "license": "Apache-2.0",
    "requires_python": ">=3.8",
    "home_page": "https://requests.readthedocs.io",
    "project_urls": {"Source": "https://github.com/psf/requests"},
    "requires_dist": ["idna", "urllib3", "certifi", "charset-normalizer"],
    "classifiers": ["Development Status :: 5 - Production/Stable"],
    "keywords": "http,requests",
}


@patch("peta.core.remote.httpx")
def test_returns_package_info(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    result = get_package("requests")
    assert isinstance(result, PackageInfo)
    assert result.name == "requests"
    assert result.source == "remote"
    assert len(result.dependencies) == 4
    assert result.files is None
    assert result.keywords == ["http", "requests"]


@patch("peta.core.remote.httpx")
def test_latest_url(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    get_package("requests")
    mock_httpx.get.assert_called_once_with(
        "https://pypi.org/pypi/requests/json", timeout=10.0
    )


@patch("peta.core.remote.httpx")
def test_specific_version_url(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    get_package("requests", version="2.28.0")
    mock_httpx.get.assert_called_once_with(
        "https://pypi.org/pypi/requests/2.28.0/json", timeout=10.0
    )


@patch("peta.core.remote.httpx")
def test_not_found(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(404)
    with pytest.raises(PackageNotFoundError):
        get_package("nope-xyz")


@patch("peta.core.remote.httpx")
def test_parses_vulnerabilities(mock_httpx: MagicMock) -> None:
    payload = {
        "info": {**_INFO, "keywords": None, "requires_dist": None},
        "vulnerabilities": [
            {"id": "PYSEC-2024-001", "aliases": ["CVE-2024-1"], "summary": "x", "fixed_in": ["1.0.1"]},
        ],
    }
    mock_httpx.get.return_value = _resp(200, payload)
    result = get_package("vuln-pkg")
    assert result.vulnerabilities[0].id == "PYSEC-2024-001"
    assert result.keywords == []
    assert result.dependencies == []


@patch("peta.core.remote.httpx")
def test_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.get.side_effect = httpx.ConnectError("refused")
    with pytest.raises(NetworkError):
        get_package("requests")


@patch("peta.core.remote.httpx")
def test_http_status_error(mock_httpx: MagicMock) -> None:
    mock_httpx.HTTPStatusError = httpx.HTTPStatusError
    mock_httpx.RequestError = httpx.RequestError
    resp = _resp(500)
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "boom", request=MagicMock(), response=MagicMock(status_code=500)
    )
    mock_httpx.get.return_value = resp
    with pytest.raises(NetworkError):
        get_package("requests")
