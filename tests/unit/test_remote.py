"""Unit tests for the PyPI remote fetcher (httpx mocked)."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.models import PackageInfo
from peta.core.remote import NetworkError, PackageNotFoundError, get_package
from tests.contract_fixtures import load_contract

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
    assert result.license == "Apache-2.0"
    assert result.license_source == "legacy"
    assert result.retrieved_at is not None


@patch("peta.core.remote.httpx")
def test_accepts_recorded_contract_and_unknown_fields(mock_httpx: MagicMock) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = load_contract("pypi-package.json")
    mock_httpx.get.return_value = response

    result = get_package("example-package")

    assert result.name == "example-package"
    assert result.vulnerabilities[0].id == "PYSEC-SYNTHETIC-1"


@patch("peta.core.remote.httpx")
def test_prefers_license_expression(mock_httpx: MagicMock) -> None:
    info = {**_INFO, "license": None, "license_expression": "MIT"}
    mock_httpx.get.return_value = _resp(200, {"info": info})

    result = get_package("requests")
    assert result.license == "MIT"
    assert result.license_source == "expression"


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
        "info": {**_INFO, "keywords": None, "requires_dist": None, "classifiers": None},
        "vulnerabilities": [
            {
                "id": "PYSEC-2024-001",
                "aliases": ["CVE-2024-1"],
                "summary": "x",
                "fixed_in": ["1.0.1"],
            }
        ],
    }
    mock_httpx.get.return_value = _resp(200, payload)
    result = get_package("vuln-pkg")
    assert result.vulnerabilities[0].id == "PYSEC-2024-001"
    assert result.keywords == []
    # An explicit null classifiers must normalize to [], not None.
    assert result.classifiers == []
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


@patch("peta.core.remote.httpx")
def test_invalid_json_raises_network_error(mock_httpx: MagicMock) -> None:
    response = _resp(200)
    response.json.side_effect = json.JSONDecodeError("bad", "", 0)
    mock_httpx.get.return_value = response

    with pytest.raises(NetworkError, match=r"PyPI.*invalid JSON"):
        get_package("requests")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"info": {}},
        {"info": {"name": None, "version": "1.0"}},
        {"info": {"name": "pkg", "version": 1}},
        {"info": {"name": "pkg", "version": "1.0", "requires_dist": [None]}},
    ],
)
@patch("peta.core.remote.httpx")
def test_malformed_metadata_raises_network_error(
    mock_httpx: MagicMock, payload: object
) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = payload
    mock_httpx.get.return_value = response

    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        get_package("pkg")
