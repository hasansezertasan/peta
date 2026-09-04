"""Unit tests for the download/dependent count clients (httpx mocked)."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.stats import (
    get_dependent_count,
    get_download_count,
    libraries_io_api_key,
)
from peta.core.validation import EnrichmentError
from tests.contract_fixtures import load_contract

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


class TestGetDownloadCount:
    @patch("peta.core.stats.httpx")
    def test_accepts_recorded_contract_and_unknown_fields(
        self, mock_httpx: MagicMock
    ) -> None:
        response = MagicMock(status_code=200)
        response.json.return_value = load_contract("pypistats.json")
        mock_httpx.get.return_value = response
        assert get_download_count("example-package") == 12345

    @patch("peta.core.stats.httpx")
    def test_happy_path(self, mock_httpx: MagicMock) -> None:
        mock_httpx.get.return_value = _resp(200, {"data": {"last_month": 12345}})
        assert get_download_count("requests") == 12345

    @patch("peta.core.stats.httpx")
    def test_404_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(404, {})
        with pytest.raises(EnrichmentError, match="pypistats: HTTP 404"):
            get_download_count("does-not-exist")

    @patch("peta.core.stats.httpx")
    def test_request_error_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.side_effect = httpx.ConnectError("refused")
        with pytest.raises(EnrichmentError, match="pypistats: refused"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_malformed_body_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"data": {}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_missing_data_key_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_non_dict_json_root_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = []
        mock_httpx.get.return_value = r
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_string_count_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"data": {"last_month": "12345"}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_bool_count_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"data": {"last_month": True}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            get_download_count("requests")

    @patch("peta.core.stats.httpx")
    def test_invalid_json_identifies_source(self, mock_httpx: MagicMock) -> None:
        response = _resp(200)
        response.json.side_effect = json.JSONDecodeError("bad", "", 0)
        mock_httpx.get.return_value = response
        with pytest.raises(EnrichmentError, match="pypistats: invalid JSON"):
            get_download_count("requests")


class TestLibrariesIoApiKey:
    def test_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LIBRARIES_IO_API_KEY", "secret-key")
        assert libraries_io_api_key() == "secret-key"

    def test_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("LIBRARIES_IO_API_KEY", raising=False)
        assert libraries_io_api_key() is None

    def test_empty_treated_as_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LIBRARIES_IO_API_KEY", "")
        assert libraries_io_api_key() is None


class TestGetDependentCount:
    @patch("peta.core.stats.httpx")
    def test_accepts_recorded_contract_and_unknown_fields(
        self, mock_httpx: MagicMock
    ) -> None:
        response = MagicMock(status_code=200)
        response.json.return_value = load_contract("libraries-io.json")
        mock_httpx.get.return_value = response
        assert get_dependent_count("example-package", api_key="secret") == 42

    @patch("peta.core.stats.httpx")
    def test_no_key_makes_no_request(self, mock_httpx: MagicMock) -> None:
        assert get_dependent_count("requests", api_key=None) is None
        mock_httpx.get.assert_not_called()

    @patch("peta.core.stats.httpx")
    def test_empty_key_makes_no_request(self, mock_httpx: MagicMock) -> None:
        assert get_dependent_count("requests", api_key="") is None
        mock_httpx.get.assert_not_called()

    @patch("peta.core.stats.httpx")
    def test_happy_path(self, mock_httpx: MagicMock) -> None:
        mock_httpx.get.return_value = _resp(200, {"dependents_count": 42})
        assert get_dependent_count("requests", api_key="secret") == 42

    @patch("peta.core.stats.httpx")
    def test_failure_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.side_effect = httpx.ConnectError("refused")
        with pytest.raises(EnrichmentError, match=r"libraries\.io: refused"):
            get_dependent_count("requests", api_key="secret")

    @patch("peta.core.stats.httpx")
    def test_non_200_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(404, {})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: HTTP 404"):
            get_dependent_count("requests", api_key="secret")

    @patch("peta.core.stats.httpx")
    def test_malformed_body_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            get_dependent_count("requests", api_key="secret")

    @patch("peta.core.stats.httpx")
    def test_string_count_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"dependents_count": "42"})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            get_dependent_count("requests", api_key="secret")

    @patch("peta.core.stats.httpx")
    def test_bool_count_identifies_source(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"dependents_count": False})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            get_dependent_count("requests", api_key="secret")

    @patch("peta.core.stats.httpx")
    def test_invalid_json_identifies_source(self, mock_httpx: MagicMock) -> None:
        response = _resp(200)
        response.json.side_effect = json.JSONDecodeError("bad", "", 0)
        mock_httpx.get.return_value = response
        with pytest.raises(EnrichmentError, match=r"libraries\.io: invalid JSON"):
            get_dependent_count("requests", api_key="secret")
