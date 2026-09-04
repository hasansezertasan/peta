"""Unit tests for the OSV vulnerability enrichment client (httpx mocked)."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.models import Vulnerability
from peta.core.osv import get_vulnerabilities
from peta.core.validation import EnrichmentError
from tests.contract_fixtures import load_contract

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
def test_accepts_recorded_contract_and_unknown_fields(mock_httpx: MagicMock) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = load_contract("osv.json")
    mock_httpx.post.return_value = response

    result = get_vulnerabilities("example-package", "1.2.3")

    assert result[0].id == "GHSA-synthetic"


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
def test_network_error_identifies_source(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.side_effect = httpx.ConnectError("refused")
    with pytest.raises(EnrichmentError, match="osv: refused"):
        get_vulnerabilities("pkg")


@patch("peta.core.osv.httpx")
def test_non_200_identifies_source(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(500, {})
    with pytest.raises(EnrichmentError, match="osv: HTTP 500"):
        get_vulnerabilities("pkg")


@patch("peta.core.osv.httpx")
def test_malformed_body_identifies_source(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(200, {"vulns": [{"no_id": True}]})
    with pytest.raises(EnrichmentError, match=r"osv: malformed response.*id"):
        get_vulnerabilities("pkg")


@patch("peta.core.osv.httpx")
def test_missing_vulns_key_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.post.return_value = _resp(200, {})
    assert get_vulnerabilities("pkg") == []


@patch("peta.core.osv.httpx")
def test_non_dict_json_root_identifies_source(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = []
    mock_httpx.post.return_value = r
    with pytest.raises(EnrichmentError, match="osv: malformed response"):
        get_vulnerabilities("pkg")


@patch("peta.core.osv.httpx")
def test_invalid_json_identifies_source(mock_httpx: MagicMock) -> None:
    response = _resp(200)
    response.json.side_effect = json.JSONDecodeError("bad", "", 0)
    mock_httpx.post.return_value = response

    with pytest.raises(EnrichmentError, match="osv: invalid JSON"):
        get_vulnerabilities("pkg")


@patch("peta.core.osv.httpx")
def test_wrong_nested_type_identifies_path(mock_httpx: MagicMock) -> None:
    payload = {"vulns": [{"id": "GHSA-1", "affected": [{"ranges": "bad"}]}]}
    mock_httpx.post.return_value = _resp(200, payload)

    with pytest.raises(EnrichmentError, match=r"affected\[0\].ranges"):
        get_vulnerabilities("pkg")
