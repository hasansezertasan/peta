"""Unit tests for the PyPI version fetcher (httpx mocked)."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.cli.commands.versions import get_versions
from peta.core.remote import NetworkError
from tests.contract_fixtures import load_contract

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


@patch("peta.cli.commands.versions.httpx")
def test_success_sorted_newest_first(mock_httpx: MagicMock) -> None:
    payload = {
        "releases": {
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "2.0.0": [{"upload_time": "2021-02-03T10:00:00"}],
            "1.5.0": [],
        }
    }
    mock_httpx.get.return_value = _resp(200, payload)
    result = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.5.0", "1.0.0"]
    assert result[0]["upload_time"] == "2021-02-03"
    # Release with no files yields an empty upload_time.
    assert result[1] == {"version": "1.5.0", "upload_time": ""}


@patch("peta.cli.commands.versions.httpx")
def test_accepts_recorded_contract_and_unknown_fields(mock_httpx: MagicMock) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = load_contract("pypi-package.json")
    mock_httpx.get.return_value = response

    assert get_versions("example-package") == [
        {"version": "1.2.3", "upload_time": "2026-01-02"}
    ]


@patch("peta.cli.commands.versions.httpx")
def test_tolerates_non_pep440_release_keys(mock_httpx: MagicMock) -> None:
    payload = {
        "releases": {
            "2.0.0": [{"upload_time": "2021-02-03T10:00:00"}],
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "not-a-version": [{"upload_time": "2019-01-01T00:00:00"}],
        }
    }
    mock_httpx.get.return_value = _resp(200, payload)
    # A single legacy key must not abort the listing with an InvalidVersion.
    result = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.0.0", "not-a-version"]


@patch("peta.cli.commands.versions.httpx")
def test_not_found_returns_empty(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(404)
    assert get_versions("nope-xyz") == []


@patch("peta.cli.commands.versions.httpx")
def test_request_error_raises_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.get.side_effect = httpx.ConnectError("refused")
    with pytest.raises(NetworkError):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_null_releases_raises_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"releases": None})
    with pytest.raises(NetworkError):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_non_dict_root_raises_network_error(mock_httpx: MagicMock) -> None:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = []
    mock_httpx.get.return_value = r
    with pytest.raises(NetworkError):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_non_list_release_entry_raises_network_error(mock_httpx: MagicMock) -> None:
    payload = {
        "releases": {
            "1.0.0": [{"upload_time": "2020-01-01T00:00:00"}],
            "2.0.0": "not-a-list",
        }
    }
    mock_httpx.get.return_value = _resp(200, payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_non_dict_release_file_member_raises_network_error(
    mock_httpx: MagicMock,
) -> None:
    payload = {"releases": {"1.0.0": [None, {"upload_time": "2020-01-01T00:00:00"}]}}
    mock_httpx.get.return_value = _resp(200, payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_non_string_upload_time_raises_network_error(mock_httpx: MagicMock) -> None:
    payload = {"releases": {"1.0.0": [{"upload_time": 12345}]}}
    mock_httpx.get.return_value = _resp(200, payload)
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_missing_releases_raises_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": {}})
    with pytest.raises(NetworkError, match="malformed response from PyPI"):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_json_decode_error_raises_network_error(mock_httpx: MagicMock) -> None:
    r = MagicMock()
    r.status_code = 200
    r.json.side_effect = json.JSONDecodeError("bad", "", 0)
    mock_httpx.get.return_value = r
    with pytest.raises(NetworkError):
        get_versions("pkg")


@patch("peta.cli.commands.versions.httpx")
def test_http_status_error_raises_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.HTTPStatusError = httpx.HTTPStatusError
    mock_httpx.RequestError = httpx.RequestError
    resp = _resp(500)
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "boom", request=MagicMock(), response=MagicMock(status_code=500)
    )
    mock_httpx.get.return_value = resp
    with pytest.raises(NetworkError):
        get_versions("pkg")
