"""Unit tests for the download/dependent count clients (httpx mocked)."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.stats import (
    get_dependent_count,
    get_download_count,
    libraries_io_api_key,
)

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


class TestGetDownloadCount:
    @patch("peta.core.stats.httpx")
    def test_happy_path(self, mock_httpx: MagicMock) -> None:
        mock_httpx.get.return_value = _resp(200, {"data": {"last_month": 12345}})
        assert get_download_count("requests") == 12345

    @patch("peta.core.stats.httpx")
    def test_404_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(404, {})
        assert get_download_count("does-not-exist") is None

    @patch("peta.core.stats.httpx")
    def test_request_error_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.side_effect = httpx.ConnectError("refused")
        assert get_download_count("requests") is None

    @patch("peta.core.stats.httpx")
    def test_malformed_body_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {"data": {}})
        assert get_download_count("requests") is None

    @patch("peta.core.stats.httpx")
    def test_missing_data_key_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {})
        assert get_download_count("requests") is None


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
    def test_failure_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.side_effect = httpx.ConnectError("refused")
        assert get_dependent_count("requests", api_key="secret") is None

    @patch("peta.core.stats.httpx")
    def test_non_200_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(404, {})
        assert get_dependent_count("requests", api_key="secret") is None

    @patch("peta.core.stats.httpx")
    def test_malformed_body_returns_none(self, mock_httpx: MagicMock) -> None:
        mock_httpx.RequestError = httpx.RequestError
        mock_httpx.get.return_value = _resp(200, {})
        assert get_dependent_count("requests", api_key="secret") is None
