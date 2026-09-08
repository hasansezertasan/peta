"""Unit tests for the version fetcher (now backed by the Simple API)."""

from typing import TYPE_CHECKING

import httpx
import pytest

from peta.cli.commands.versions import get_versions
from peta.core.remote import NetworkError
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit


def _simple_page(
    versions: list[str], files: list[object] | None = None
) -> dict[str, object]:
    return {
        "meta": {"api-version": "1.1"},
        "name": "pkg",
        "versions": versions,
        "files": files or [],
    }


def test_success_sorted_newest_first(fake_http: FakeTransport) -> None:
    payload = _simple_page(
        ["1.0.0", "2.0.0", "1.5.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.0.tar.gz",
                "hashes": {},
                "upload-time": "2020-01-01T00:00:00Z",
            },
            {
                "filename": "pkg-2.0.0.tar.gz",
                "url": "https://example.invalid/pkg-2.0.0.tar.gz",
                "hashes": {},
                "upload-time": "2021-02-03T10:00:00Z",
            },
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.5.0", "1.0.0"]
    assert result[0]["upload_time"] == "2021-02-03"
    assert result[1] == {"version": "1.5.0", "upload_time": ""}


def test_accepts_recorded_contract_and_unknown_fields(fake_http: FakeTransport) -> None:
    fake_http.reply(json=load_contract("pypi-simple.json"))

    versions, provenance = get_versions("example-package")
    assert versions == [{"version": "1.2.3", "upload_time": "2026-01-02"}]
    assert provenance.freshness == "live"


def test_tolerates_non_pep440_version_strings(fake_http: FakeTransport) -> None:
    payload = _simple_page(["2.0.0", "1.0.0", "not-a-version"])
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert [r["version"] for r in result] == ["2.0.0", "1.0.0", "not-a-version"]


def test_not_found_returns_empty(fake_http: FakeTransport) -> None:
    fake_http.reply(status=404)
    versions, provenance = get_versions("nope-xyz")
    assert versions == []
    assert provenance.freshness == "live"


def test_request_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.fail(httpx.ConnectError("refused"))
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_non_dict_root_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json=[])
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_missing_versions_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"name": "pkg"})
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_missing_name_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"versions": []})
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_non_string_version_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"name": "pkg", "versions": [123]})
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_file_missing_filename_raises_network_error(fake_http: FakeTransport) -> None:
    payload = _simple_page(["1.0.0"], [{"url": "https://example.invalid/x"}])
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_file_non_string_upload_time_raises_network_error(
    fake_http: FakeTransport,
) -> None:
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.0.tar.gz",
                "hashes": {},
                "upload-time": 12345,
            }
        ],
    )
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_json_decode_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(text="not json at all")
    with pytest.raises(NetworkError):
        _ = get_versions("pkg")


def test_http_status_error_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(status=500)
    with pytest.raises(NetworkError, match="Simple API returned HTTP 500"):
        _ = get_versions("pkg")


def test_yanked_files_still_listed(fake_http: FakeTransport) -> None:
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.0.tar.gz",
                "hashes": {},
                "yanked": "security issue",
                "upload-time": "2020-06-01T00:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": "2020-06-01"}]


def test_version_with_no_files_has_empty_upload_time(fake_http: FakeTransport) -> None:
    payload = _simple_page(["1.0.0", "2.0.0"])
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert all(not r["upload_time"] for r in result)


def test_sends_pep691_accept_header(fake_http: FakeTransport) -> None:
    payload = _simple_page(["1.0.0"])
    fake_http.reply(json=payload)
    _ = get_versions("pkg")
    assert fake_http.request.headers["accept"] == "application/vnd.pypi.simple.v1+json"


def test_url_uses_canonical_name(fake_http: FakeTransport) -> None:
    payload = _simple_page(["1.0.0"])
    fake_http.reply(json=payload)
    _ = get_versions("Zope.Interface")
    assert "/zope-interface/" in str(fake_http.request.url)


def test_upload_time_from_wheel_filename(fake_http: FakeTransport) -> None:
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.0-py3-none-any.whl",
                "url": "https://example.invalid/pkg-1.0.0-py3-none-any.whl",
                "hashes": {},
                "upload-time": "2023-03-15T12:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result[0]["upload_time"] == "2023-03-15"


def test_missing_optional_file_fields(fake_http: FakeTransport) -> None:
    """Files with no optional fields still parse without error."""
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.0.tar.gz",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": ""}]


def test_non_dict_file_member_raises_network_error(fake_http: FakeTransport) -> None:
    payload = _simple_page(["1.0.0"], ["not-a-dict"])
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_non_list_files_raises_network_error(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"name": "pkg", "versions": ["1.0.0"], "files": "bad"})
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_version_normalization_matches_upload_time(fake_http: FakeTransport) -> None:
    """A filename whose version normalizes differently still matches."""
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.tar.gz",
                "hashes": {},
                "upload-time": "2020-05-10T00:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": "2020-05-10"}]


def _file(overrides: dict[str, object] | None = None) -> dict[str, object]:
    base: dict[str, object] = {
        "filename": "pkg-1.0.0.tar.gz",
        "url": "https://example.invalid/pkg-1.0.0.tar.gz",
        "hashes": {},
    }
    if overrides:
        base.update(overrides)
    return base


@pytest.mark.parametrize(
    ("field", "value"),
    [("requires-python", 99), ("size", "big"), ("yanked", 1), ("provenance", 42)],
)
def test_file_bad_scalar_raises_network_error(
    fake_http: FakeTransport, field: str, value: object
) -> None:
    payload = _simple_page(["1.0.0"], [_file({field: value})])
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_file_non_string_hash_value_raises_network_error(
    fake_http: FakeTransport,
) -> None:
    payload = _simple_page(["1.0.0"], [_file({"hashes": {"sha256": 123}})])
    fake_http.reply(json=payload)
    with pytest.raises(NetworkError, match="malformed response from Simple API"):
        _ = get_versions("pkg")


def test_unrecognized_extension_omits_upload_time(fake_http: FakeTransport) -> None:
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.bz2",
                "url": "https://example.invalid/pkg-1.0.0.tar.bz2",
                "hashes": {},
                "upload-time": "2020-01-01T00:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": ""}]


def test_invalid_wheel_filename_omits_upload_time(fake_http: FakeTransport) -> None:
    payload = _simple_page(
        ["1.0.0"],
        [
            {
                "filename": "bad.whl",
                "url": "https://example.invalid/bad.whl",
                "hashes": {},
                "upload-time": "2020-01-01T00:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": ""}]


def test_file_version_not_in_versions_list_omits_upload_time(
    fake_http: FakeTransport,
) -> None:
    payload = _simple_page(
        ["2.0.0"],
        [
            {
                "filename": "pkg-1.0.0.tar.gz",
                "url": "https://example.invalid/pkg-1.0.0.tar.gz",
                "hashes": {},
                "upload-time": "2020-01-01T00:00:00Z",
            }
        ],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "2.0.0", "upload_time": ""}]


def test_dist_info_metadata_fallback(fake_http: FakeTransport) -> None:
    """The legacy dist-info-metadata key is read when core-metadata is absent."""
    payload = _simple_page(
        ["1.0.0"],
        [_file({"dist-info-metadata": True, "upload-time": "2020-01-01T00:00:00Z"})],
    )
    fake_http.reply(json=payload)
    result, _ = get_versions("pkg")
    assert result == [{"version": "1.0.0", "upload_time": "2020-01-01"}]
