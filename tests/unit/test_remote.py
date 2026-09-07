"""Unit tests for the PyPI remote fetcher (served by a canned transport)."""

from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core.models import PackageInfo
from peta.core.remote import NetworkError, PackageNotFoundError, get_package
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


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


def test_returns_package_info(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"info": _INFO, "vulnerabilities": []})
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


def test_accepts_recorded_contract_and_unknown_fields(fake_http: FakeTransport) -> None:
    fake_http.reply(json=load_contract("pypi-package.json"))

    result = get_package("example-package")

    assert result.name == "example-package"
    assert result.vulnerabilities[0].id == "PYSEC-SYNTHETIC-1"


def test_prefers_license_expression(fake_http: FakeTransport) -> None:
    info = {**_INFO, "license": None, "license_expression": "MIT"}
    fake_http.reply(json={"info": info})

    result = get_package("requests")
    assert result.license == "MIT"
    assert result.license_source == "expression"


def test_latest_url(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"info": _INFO, "vulnerabilities": []})
    _ = get_package("requests")
    assert str(fake_http.request.url) == "https://pypi.org/pypi/requests/json"


def test_specific_version_url(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"info": _INFO, "vulnerabilities": []})
    _ = get_package("requests", version="2.28.0")
    assert str(fake_http.request.url) == "https://pypi.org/pypi/requests/2.28.0/json"


def test_not_found(fake_http: FakeTransport) -> None:
    fake_http.reply(status=404)
    with pytest.raises(PackageNotFoundError):
        _ = get_package("nope-xyz")


def test_parses_vulnerabilities(fake_http: FakeTransport) -> None:
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
    fake_http.reply(json=payload)
    result = get_package("vuln-pkg")
    assert result.vulnerabilities[0].id == "PYSEC-2024-001"
    assert result.keywords == []
    # An explicit null classifiers must normalize to [], not None.
    assert result.classifiers == []
    assert result.dependencies == []


def test_network_error(fake_http: FakeTransport) -> None:
    fake_http.fail(httpx.ConnectError("refused"))
    with pytest.raises(NetworkError):
        _ = get_package("requests")


def test_http_status_error(fake_http: FakeTransport) -> None:
    fake_http.reply(status=500)
    with pytest.raises(NetworkError, match="PyPI returned HTTP 500"):
        _ = get_package("requests")


def test_invalid_json_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(text="not json at all")

    with pytest.raises(NetworkError, match=r"PyPI.*invalid JSON"):
        _ = get_package("requests")


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
def test_malformed_metadata_raises_network_error(
    fake_http: FakeTransport, payload: object
) -> None:
    fake_http.reply(json=payload)

    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_package("pkg")
