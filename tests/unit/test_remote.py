"""Unit tests for the PyPI remote fetcher (served by a canned transport)."""

import re
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import httpx
import pytest
from packaging.specifiers import SpecifierSet

from peta.core.models import PackageInfo
from peta.core.remote import (
    NetworkError,
    PackageNotFoundError,
    get_package,
    get_package_matching,
)
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


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_prefers_stable_versions(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"1.9": [{"yanked": False}], "2.0rc1": [{"yanked": False}]}},
        MagicMock(),
    )
    get.side_effect = lambda _name, version: PackageInfo(
        name="dep", version=version, source="remote"
    )

    result = get_package_matching("dep", SpecifierSet("<2"), None)

    assert result.version == "1.9"
    get.assert_called_once_with("dep", "1.9")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_excludes_implicit_prerelease(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = ({"releases": {"1.9rc1": [{"yanked": False}]}}, MagicMock())
    current = PackageInfo(name="dep", version="2.0", source="remote")
    get.return_value = current

    result = get_package_matching("dep", SpecifierSet("<2"), None)

    assert result is current
    get.assert_called_once_with("dep")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_accepts_explicit_prerelease(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = ({"releases": {"1.9rc1": [{"yanked": False}]}}, MagicMock())
    prerelease = PackageInfo(name="dep", version="1.9rc1", source="remote")
    get.return_value = prerelease

    result = get_package_matching("dep", SpecifierSet(">=1.9rc1,<2"), None)

    assert result is prerelease
    get.assert_called_once_with("dep", "1.9rc1")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_unconstrained_matching_prefers_final_release(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"1.9": [{"yanked": False}], "2.0rc1": [{"yanked": False}]}},
        MagicMock(),
    )
    get.side_effect = lambda _name, version: PackageInfo(
        name="dep", version=version, source="remote"
    )

    result = get_package_matching("dep", SpecifierSet(), None)

    assert result.version == "1.9"
    get.assert_called_once_with("dep", "1.9")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_reuses_current_project_metadata(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {
            "info": {**_INFO, "name": "dep", "version": "1.9"},
            "releases": {"1.9": [{"yanked": False}]},
        },
        MagicMock(retrieved_at="now", freshness="live"),
    )

    result = get_package_matching("dep", SpecifierSet(), None)

    assert result.version == "1.9"
    get.assert_not_called()


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_skips_fully_yanked_ordinary_release(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"2.0": [{"yanked": True}], "1.9": [{"yanked": False}]}},
        MagicMock(),
    )
    get.side_effect = lambda _name, version: PackageInfo(
        name="dep", version=version, source="remote"
    )

    result = get_package_matching("dep", SpecifierSet(), None)

    assert result.version == "1.9"
    get.assert_called_once_with("dep", "1.9")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_accepts_fully_yanked_exact_pin(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"2.0": [{"yanked": True}], "1.9": [{"yanked": False}]}},
        MagicMock(),
    )
    get.side_effect = lambda _name, version: PackageInfo(
        name="dep", version=version, source="remote"
    )

    result = get_package_matching("dep", SpecifierSet("==2.0"), None)

    assert result.version == "2.0"
    get.assert_called_once_with("dep", "2.0")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_skips_release_without_distribution_files(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"2.0": [], "1.9": [{"yanked": False}]}},
        MagicMock(),
    )
    get.side_effect = lambda _name, version: PackageInfo(
        name="dep", version=version, source="remote"
    )

    result = get_package_matching("dep", SpecifierSet(), None)

    assert result.version == "1.9"
    get.assert_called_once_with("dep", "1.9")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_skips_releases_incompatible_with_running_python(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"2.0": [{"yanked": False}], "1.0": [{"yanked": False}]}},
        MagicMock(),
    )
    pkgs = {
        "2.0": PackageInfo(
            name="dep", version="2.0", source="remote", python_requires=">=4.0"
        ),
        "1.0": PackageInfo(name="dep", version="1.0", source="remote"),
    }
    get.side_effect = lambda _name, version: pkgs[version]

    result = get_package_matching("dep", SpecifierSet(), None)
    assert result.version == "1.0"


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_skips_invalid_versions_and_falls_back(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = ({"releases": {"not-a-version": [], "2.0": []}}, MagicMock())
    current = PackageInfo(name="dep", version="3.0", source="remote")
    get.return_value = current

    result = get_package_matching("dep", SpecifierSet("<2"), None)

    assert result is current
    get.assert_called_once_with("dep")


@patch("peta.core.remote.get_package")
@patch("peta.core.remote._fetch")
def test_matching_release_rejects_invalid_requires_python(
    fetch: MagicMock, get: MagicMock
) -> None:
    fetch.return_value = (
        {"releases": {"2.0": [{"yanked": False}], "1.0": [{"yanked": False}]}},
        MagicMock(),
    )
    packages = {
        "2.0": PackageInfo(
            name="dep", version="2.0", source="remote", python_requires="invalid"
        ),
        "1.0": PackageInfo(name="dep", version="1.0", source="remote"),
    }
    get.side_effect = lambda _name, version=None: packages.get(version, packages["1.0"])

    result = get_package_matching(
        "dep", SpecifierSet(), {"python_full_version": "3.12.0"}
    )

    assert result.version == "1.0"


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
                "summary": "something bad",
                "fixed_in": ["2.32.0"],
            }
        ],
    }
    fake_http.reply(json=payload)

    pkg = get_package("requests")

    assert len(pkg.vulnerabilities) == 1
    vuln = pkg.vulnerabilities[0]
    assert vuln.id == "PYSEC-2024-001"
    assert vuln.aliases == ["CVE-2024-1"]
    assert vuln.summary == "something bad"
    assert vuln.fixed_in == ["2.32.0"]


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
        {"info": {"name": "pkg", "version": "1.0"}, "releases": None},
        {"info": {"name": "pkg", "version": "1.0"}, "releases": []},
        {"info": {"name": "pkg", "version": "1.0"}, "releases": {"1.0": None}},
        {"info": {"name": "pkg", "version": "1.0"}, "releases": {"1.0": [None]}},
        {
            "info": {"name": "pkg", "version": "1.0"},
            "releases": {"1.0": [{"yanked": 1}]},
        },
    ],
)
def test_malformed_metadata_raises_network_error(
    fake_http: FakeTransport, payload: object
) -> None:
    fake_http.reply(json=payload)

    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_package("pkg")


class TestCanonicalNames:
    @pytest.mark.parametrize(
        "spelling", ["Zope.Interface", "zope_interface", "ZOPE-INTERFACE"]
    )
    def test_equivalent_spellings_request_one_url(
        self, fake_http: FakeTransport, spelling: str
    ) -> None:
        # PyPI serves every spelling identically, but they are different URLs,
        # so caching by raw name would store the same response repeatedly and
        # let an offline lookup miss an entry it already holds.
        fake_http.reply(json={"info": {"name": "zope.interface", "version": "6.0"}})

        _ = get_package(spelling)

        assert str(fake_http.request.url) == "https://pypi.org/pypi/zope-interface/json"

    def test_a_version_is_left_alone(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"info": {"name": "typing-extensions", "version": "4.0"}})

        _ = get_package("typing_extensions", version="4.0.0")

        assert str(fake_http.request.url).endswith("/typing-extensions/4.0.0/json")

    def test_the_users_spelling_survives_in_the_error(
        self, fake_http: FakeTransport
    ) -> None:
        # Only the request is canonicalized; a message should echo what was
        # actually typed.
        fake_http.reply(status=404)

        with pytest.raises(PackageNotFoundError, match=re.escape("Zope.Interface")):
            _ = get_package("Zope.Interface")
