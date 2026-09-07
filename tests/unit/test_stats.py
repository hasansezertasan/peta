"""Unit tests for the count clients (served by a canned transport)."""

from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import cache
from peta.core.stats import (
    get_dependent_count,
    get_download_count,
    libraries_io_api_key,
)
from peta.core.validation import EnrichmentError
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from pathlib import Path

    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


class TestGetDownloadCount:
    def test_accepts_recorded_contract_and_unknown_fields(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=load_contract("pypistats.json"))
        assert get_download_count("example-package") == (12345, "live")

    def test_happy_path(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"data": {"last_month": 12345}})
        assert get_download_count("requests") == (12345, "live")

    def test_404_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(status=404, json={})
        with pytest.raises(EnrichmentError, match="pypistats: HTTP 404"):
            _ = get_download_count("does-not-exist")

    def test_request_error_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.fail(httpx.ConnectError("refused"))
        with pytest.raises(EnrichmentError, match="pypistats: refused"):
            _ = get_download_count("requests")

    def test_malformed_body_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"data": {}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            _ = get_download_count("requests")

    def test_missing_data_key_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            _ = get_download_count("requests")

    def test_non_dict_json_root_identifies_source(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=[])
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            _ = get_download_count("requests")

    def test_string_count_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"data": {"last_month": "12345"}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            _ = get_download_count("requests")

    def test_bool_count_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"data": {"last_month": True}})
        with pytest.raises(EnrichmentError, match="pypistats: malformed response"):
            _ = get_download_count("requests")

    def test_invalid_json_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(text="not json at all")
        with pytest.raises(EnrichmentError, match="pypistats: invalid JSON"):
            _ = get_download_count("requests")


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
    def test_accepts_recorded_contract_and_unknown_fields(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=load_contract("libraries-io.json"))
        assert get_dependent_count("example-package", api_key="secret") == (42, "live")

    def test_no_key_makes_no_request(self, fake_http: FakeTransport) -> None:
        assert get_dependent_count("requests", api_key=None) == (None, "live")
        assert fake_http.requests == []

    def test_empty_key_makes_no_request(self, fake_http: FakeTransport) -> None:
        assert get_dependent_count("requests", api_key="") == (None, "live")
        assert fake_http.requests == []

    def test_happy_path(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"dependents_count": 42})
        assert get_dependent_count("requests", api_key="secret") == (42, "live")

    def test_sends_the_key_as_a_query_parameter(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"dependents_count": 42})
        _ = get_dependent_count("requests", api_key="secret")
        assert fake_http.request.url.params["api_key"] == "secret"

    def test_failure_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.fail(httpx.ConnectError("refused"))
        with pytest.raises(EnrichmentError, match=r"libraries\.io: refused"):
            _ = get_dependent_count("requests", api_key="secret")

    def test_non_200_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(status=404, json={})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: HTTP 404"):
            _ = get_dependent_count("requests", api_key="secret")

    def test_malformed_body_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            _ = get_dependent_count("requests", api_key="secret")

    def test_string_count_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"dependents_count": "42"})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            _ = get_dependent_count("requests", api_key="secret")

    def test_bool_count_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={"dependents_count": False})
        with pytest.raises(EnrichmentError, match=r"libraries\.io: malformed response"):
            _ = get_dependent_count("requests", api_key="secret")

    def test_invalid_json_identifies_source(self, fake_http: FakeTransport) -> None:
        fake_http.reply(text="not json at all")
        with pytest.raises(EnrichmentError, match=r"libraries\.io: invalid JSON"):
            _ = get_dependent_count("requests", api_key="secret")


class TestOffline:
    def test_a_download_count_lookup_reports_offline_as_a_source_failure(
        self, cache_dir: Path
    ) -> None:
        # Counts are optional enrichment, so being offline must surface as a
        # named source failure rather than aborting the command.
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(EnrichmentError, match="pypistats: offline"):
            _ = get_download_count("requests")

    def test_a_dependent_count_lookup_reports_offline_as_a_source_failure(
        self, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(EnrichmentError, match=r"libraries\.io: offline"):
            _ = get_dependent_count("requests", api_key="secret")
