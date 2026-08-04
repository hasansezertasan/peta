"""Unit tests for the OSV vulnerability enrichment client (httpx mocked)."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.models import Vulnerability
from peta.core.osv import get_vulnerabilities

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


_PAYLOAD = {
    "vulns": [
        {
            "id": "GHSA-xxxx",
            "aliases": ["CVE-2024-9999"],
            "summary": "A bad thing.",
            "affected": [
                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]},
                {"ranges": [{"events": [{"fixed": "1.2.3"}, {"fixed": "1.3.0"}]}]},
            ],
            "severity": [{"type": "CVSS_V3", "score": "AV:N/AC:L"}],
        }
    ]
}


@patch("peta.core.osv.httpx")
def test_maps_fields(mock_httpx: MagicMock) -> None:
    mock_httpx.post.return_value = _resp(200, _PAYLOAD)
    result = get_vulnerabilities("evil-pkg", "1.0.0")
    assert len(result) == 1
    v = result[0]
    assert isinstance(v, Vulnerability)
    assert v.id == "GHSA-xxxx"
    assert v.aliases == ["CVE-2024-9999"]
    assert v.summary == "A bad thing."
    assert v.fixed_in == ["1.2.3", "1.3.0"]
    assert v.severity == "AV:N/AC:L"


@patch("peta.core.osv.httpx")
def test_summary_falls_back_to_details(mock_httpx: MagicMock) -> None:
    payload = {"vulns": [{"id": "GHSA-1", "details": "details text", "affected": []}]}
    mock_httpx.post.return_value = _resp(200, payload)
    result = get_vulnerabilities("pkg")
    assert result[0].summary == "details text"
    assert result[0].aliases == []
    assert result[0].fixed_in == []
    assert result[0].severity is None


@patch("peta.core.osv.httpx")
def test_summary_defaults_to_empty(mock_httpx: MagicMock) -> None:
    payload = {"vulns": [{"id": "GHSA-2", "affected": []}]}
    mock_httpx.post.return_value = _resp(200, payload)
    result = get_vulnerabilities("pkg")
    assert not result[0].summary


@patch("peta.core.osv.httpx")
def test_severity_none_when_empty_list(mock_httpx: MagicMock) -> None:
    payload = {"vulns": [{"id": "GHSA-3", "affected": [], "severity": []}]}
    mock_httpx.post.return_value = _resp(200, payload)
    result = get_vulnerabilities("pkg")
    assert result[0].severity is None


@patch("peta.core.osv.httpx")
def test_version_none_omits_version_key(mock_httpx: MagicMock) -> None:
    mock_httpx.post.return_value = _resp(200, {"vulns": []})
    get_vulnerabilities("pkg")
    _, kwargs = mock_httpx.post.call_args
    body = kwargs["json"]
    assert "version" not in body
    assert body["package"] == {"name": "pkg", "ecosystem": "PyPI"}


@patch("peta.core.osv.httpx")
def test_version_included_when_given(mock_httpx: MagicMock) -> None:
    mock_httpx.post.return_value = _resp(200, {"vulns": []})
    get_vulnerabilities("pkg", "2.0.0")
    _, kwargs = mock_httpx.post.call_args
    assert kwargs["json"]["version"] == "2.0.0"


@patch("peta.core.osv.httpx")
def test_network_error_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.side_effect = httpx.ConnectError("refused")
    assert get_vulnerabilities("pkg") == []


@patch("peta.core.osv.httpx")
def test_non_200_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(500, {})
    assert get_vulnerabilities("pkg") == []


@patch("peta.core.osv.httpx")
def test_malformed_body_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(200, {"vulns": [{"no_id": True}]})
    assert get_vulnerabilities("pkg") == []


@patch("peta.core.osv.httpx")
def test_missing_vulns_key_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(200, {})
    assert get_vulnerabilities("pkg") == []
