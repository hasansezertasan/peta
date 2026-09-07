"""Unit tests for the OSV enrichment client (served by a canned transport)."""

import json
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from peta.core.models import Vulnerability
from peta.core.osv import get_vulnerabilities
from peta.core.validation import EnrichmentError
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


def _posted_body(fake_http: FakeTransport) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(fake_http.request.content))


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


def test_maps_fields(fake_http: FakeTransport) -> None:
    fake_http.reply(json=_PAYLOAD)
    result = get_vulnerabilities("evil-pkg", "1.0.0")
    assert len(result) == 1
    v = result[0]
    assert isinstance(v, Vulnerability)
    assert v.id == "GHSA-xxxx"
    assert v.aliases == ["CVE-2024-9999"]
    assert v.summary == "A bad thing."
    assert v.fixed_in == ["1.2.3", "1.3.0"]
    assert v.severity == "AV:N/AC:L"


def test_accepts_recorded_contract_and_unknown_fields(fake_http: FakeTransport) -> None:
    fake_http.reply(json=load_contract("osv.json"))

    result = get_vulnerabilities("example-package", "1.2.3")

    assert result[0].id == "GHSA-synthetic"


def test_summary_falls_back_to_details(fake_http: FakeTransport) -> None:
    payload = {"vulns": [{"id": "GHSA-1", "details": "details text", "affected": []}]}
    fake_http.reply(json=payload)
    result = get_vulnerabilities("pkg")
    assert result[0].summary == "details text"
    assert result[0].aliases == []
    assert result[0].fixed_in == []
    assert result[0].severity is None


def test_summary_defaults_to_empty(fake_http: FakeTransport) -> None:
    payload = {"vulns": [{"id": "GHSA-2", "affected": []}]}
    fake_http.reply(json=payload)
    result = get_vulnerabilities("pkg")
    assert not result[0].summary


def test_severity_none_when_empty_list(fake_http: FakeTransport) -> None:
    payload = {"vulns": [{"id": "GHSA-3", "affected": [], "severity": []}]}
    fake_http.reply(json=payload)
    result = get_vulnerabilities("pkg")
    assert result[0].severity is None


def test_version_none_omits_version_key(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"vulns": []})
    _ = get_vulnerabilities("pkg")
    body = _posted_body(fake_http)
    assert "version" not in body
    assert body["package"] == {"name": "pkg", "ecosystem": "PyPI"}


def test_version_included_when_given(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"vulns": []})
    _ = get_vulnerabilities("pkg", "2.0.0")
    assert _posted_body(fake_http)["version"] == "2.0.0"


def test_network_error_identifies_source(fake_http: FakeTransport) -> None:
    fake_http.fail(httpx.ConnectError("refused"))
    with pytest.raises(EnrichmentError, match="osv: refused"):
        _ = get_vulnerabilities("pkg")


def test_non_200_identifies_source(fake_http: FakeTransport) -> None:
    fake_http.reply(status=500, json={})
    with pytest.raises(EnrichmentError, match="osv: HTTP 500"):
        _ = get_vulnerabilities("pkg")


def test_malformed_body_identifies_source(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"vulns": [{"no_id": True}]})
    with pytest.raises(EnrichmentError, match=r"osv: malformed response.*id"):
        _ = get_vulnerabilities("pkg")


def test_missing_vulns_key_returns_empty(fake_http: FakeTransport) -> None:
    fake_http.reply(json={})
    assert get_vulnerabilities("pkg") == []


def test_non_dict_json_root_identifies_source(fake_http: FakeTransport) -> None:
    fake_http.reply(json=[])
    with pytest.raises(EnrichmentError, match="osv: malformed response"):
        _ = get_vulnerabilities("pkg")


def test_invalid_json_identifies_source(fake_http: FakeTransport) -> None:
    fake_http.reply(text="not json at all")

    with pytest.raises(EnrichmentError, match="osv: invalid JSON"):
        _ = get_vulnerabilities("pkg")


def test_wrong_nested_type_identifies_path(fake_http: FakeTransport) -> None:
    payload = {"vulns": [{"id": "GHSA-1", "affected": [{"ranges": "bad"}]}]}
    fake_http.reply(json=payload)

    with pytest.raises(EnrichmentError, match=r"affected\[0\].ranges"):
        _ = get_vulnerabilities("pkg")
