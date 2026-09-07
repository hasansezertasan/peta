"""Unit tests for the PyPI version fetcher (served by a canned transport)."""

from typing import TYPE_CHECKING

import httpx
import pytest

from peta.cli.commands.versions import get_versions
from peta.core.remote import NetworkError
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


def test_success_sorted_newest_first(fake_http: FakeTransport) -> None:
    payload = {
        "releases": {
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "2.0.0": [{"upload_time": "2021-02-03T10:00:00"}],
            "1.5.0": [],
        }
    }
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.5.0", "1.0.0"]
    assert result[0]["upload_time"] == "2021-02-03"
    # Release with no files yields an empty upload_time.
    assert result[1] == {"version": "1.5.0", "upload_time": ""}


def test_accepts_recorded_contract_and_unknown_fields(fake_http: FakeTransport) -> None:
    fake_http.reply(json=load_contract("pypi-package.json"))

    assert get_versions("example-package") == (
        [{"version": "1.2.3", "upload_time": "2026-01-02"}],
        "live",
    )


def test_tolerates_non_pep440_release_keys(fake_http: FakeTransport) -> None:
    payload = {
        "releases": {
            "2.0.0": [{"upload_time": "2021-02-03T10:00:00"}],
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "not-a-version": [{"upload_time": "2019-01-01T00:00:00"}],
        }
    }
    fake_http.reply(json=payload)
    # A single legacy key must not abort the listing with an InvalidVersion.
    result, _ = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.0.0", "not-a-version"]


def test_not_found_returns_empty(fake_http: FakeTransport) -> None:
    fake_http.reply(status=404)
    assert get_versions("nope-xyz") == ([], "live")


def test_request_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.fail(httpx.ConnectError("refused"))
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_null_releases_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"releases": None})
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_non_dict_root_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json=[])
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_non_list_release_entry_raises_network_error(fake_http: FakeTransport) -> None:
    payload = {
        "releases": {
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "2.0.0": "not-a-list",
        }
    }
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_versions("pkg")


def test_non_dict_release_file_member_raises_network_error(
    fake_http: FakeTransport,
) -> None:
    payload = {"releases": {"1.0.0": [None, {"upload_time": "2020-01-01T00:00:00"}]}}
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_versions("pkg")


def test_non_string_upload_time_raises_network_error(fake_http: FakeTransport) -> None:
    payload = {"releases": {"1.0.0": [{"upload_time": 12345}]}}
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_versions("pkg")


def test_missing_releases_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"info": {}})
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        _ = get_versions("pkg")


def test_json_decode_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(text="not json at all")
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_http_status_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(status=500)
    with pytest.raises(NetworkError, match="PyPI returned HTTP 500"):
        _ = get_versions("pkg")
