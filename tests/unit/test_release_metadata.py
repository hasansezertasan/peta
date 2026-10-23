"""Unit tests for Core Metadata read from PEP 658 ``.metadata`` files."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import http
from peta.core.models import CoreMetadata, PackageInfo, Person
from peta.core.release_metadata import SOURCE_NAME, attach_release_metadata

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit

_WHEEL = "https://files.example/demo-1.0-py3-none-any.whl"
_SDIST = "https://files.example/demo-1.0.tar.gz"


def _metadata(
    version: str = "2.4", *extra: tuple[str, str], body: str = "Long text.\n"
) -> str:
    headers = [
        ("Metadata-Version", version),
        ("Name", "demo"),
        ("Version", "1.0"),
        ("Author-email", "Ada <ada@example.com>"),
        ("Import-Name", "demo"),
        ("Import-Namespace", "ns.demo"),
        ("License-File", "LICENSE"),
        ("Provides-Extra", "cli"),
        *extra,
    ]
    return "".join(f"{k}: {v}\n" for k, v in headers) + f"\n{body}"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _page(*files: dict[str, object]) -> dict[str, object]:
    return {"name": "demo", "versions": ["1.0"], "files": list(files)}


def _file(url: str, *, core_metadata: object) -> dict[str, object]:
    return {
        "filename": url.rsplit("/", 1)[1],
        "url": f"{url}#sha256=ignored",
        "hashes": {"sha256": "0" * 64},
        "core-metadata": core_metadata,
    }


def _package() -> PackageInfo:
    return PackageInfo(
        name="demo",
        version="1.0",
        source="remote",
        core_metadata=CoreMetadata(
            source="pypi", authors=[Person("Ada", "ada@example.com")]
        ),
    )


def test_a_modern_metadata_file_fills_what_the_json_api_omits(
    fake_http: FakeTransport,
) -> None:
    text = _metadata("2.4")
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    fake_http.reply(url=f"{_WHEEL}.metadata", text=text)
    result = attach_release_metadata(_package())
    meta = result.core_metadata
    assert meta is not None
    assert meta.source == "release_metadata"
    assert meta.metadata_version == "2.4"
    assert meta.import_names == ["demo"]
    assert meta.import_namespaces == ["ns.demo"]
    assert meta.entry_points == []
    assert meta.authors == [Person("Ada", "ada@example.com")]
    record = result.enrichment_sources[-1]
    assert (record.name, record.state) == (SOURCE_NAME, "success")
    assert record.fields == ["result.core_metadata"]
    assert result.enrichment_failures == []


def test_a_newer_revision_and_an_unknown_header_are_kept_verbatim(
    fake_http: FakeTransport,
) -> None:
    text = _metadata("9.9", ("Future-Field", "a"), ("Future-Field", "b"))
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    fake_http.reply(url=f"{_WHEEL}.metadata", text=text)
    meta = attach_release_metadata(_package()).core_metadata
    assert meta is not None
    assert meta.metadata_version == "9.9"
    assert meta.unrecognized == {"Future-Field": ["a", "b"]}


def test_the_description_body_is_never_read_as_headers(
    fake_http: FakeTransport,
) -> None:
    text = _metadata(body="Import-Name: injected\n")
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    fake_http.reply(url=f"{_WHEEL}.metadata", text=text)
    meta = attach_release_metadata(_package()).core_metadata
    assert meta is not None
    assert meta.import_names == ["demo"]


def test_a_hash_mismatch_is_a_failure_and_never_data(fake_http: FakeTransport) -> None:
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": "0" * 64})),
    )
    fake_http.reply(url=f"{_WHEEL}.metadata", text=_metadata("2.4"))
    package = _package()
    result = attach_release_metadata(package)
    assert result.core_metadata == package.core_metadata
    (failure,) = result.enrichment_failures
    assert failure.source == SOURCE_NAME
    assert "hash" in failure.reason
    record = result.enrichment_sources[-1]
    assert (record.name, record.state) == (SOURCE_NAME, "failed")


def test_a_weak_only_hash_is_not_trusted(fake_http: FakeTransport) -> None:
    text = _metadata()
    md5 = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
    fake_http.reply(
        url="/simple/demo/", json=_page(_file(_WHEEL, core_metadata={"md5": md5}))
    )
    package = _package()
    assert attach_release_metadata(package) == package
    assert len(fake_http.requests) == 1


def test_an_unhashed_advertisement_is_passed_over(fake_http: FakeTransport) -> None:
    fake_http.reply(url="/simple/demo/", json=_page(_file(_WHEEL, core_metadata=True)))
    package = _package()
    assert attach_release_metadata(package) == package
    assert len(fake_http.requests) == 1


def test_a_release_without_advertised_metadata_keeps_the_json_values(
    fake_http: FakeTransport,
) -> None:
    fake_http.reply(url="/simple/demo/", json=_page(_file(_WHEEL, core_metadata=False)))
    package = _package()
    assert attach_release_metadata(package) == package


def test_a_wheel_is_preferred_over_an_sdist(fake_http: FakeTransport) -> None:
    text = _metadata()
    digest = {"sha256": _sha256(text)}
    fake_http.reply(
        url="/simple/demo/",
        json=_page(
            _file(_SDIST, core_metadata=digest), _file(_WHEEL, core_metadata=digest)
        ),
    )
    fake_http.reply(url=".metadata", text=text)
    _ = attach_release_metadata(_package())
    assert str(fake_http.requests[-1].url) == f"{_WHEEL}.metadata"


def test_a_failed_download_is_a_failure(fake_http: FakeTransport) -> None:
    text = _metadata()
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    fake_http.fail(httpx.ConnectError("boom"), url=".metadata")
    result = attach_release_metadata(_package())
    assert [failure.source for failure in result.enrichment_failures] == [SOURCE_NAME]


def test_a_file_without_a_revision_is_refused(fake_http: FakeTransport) -> None:
    text = "Name: demo\n\nbody\n"
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    fake_http.reply(url=f"{_WHEEL}.metadata", text=text)
    result = attach_release_metadata(_package())
    (failure,) = result.enrichment_failures
    assert "Metadata-Version" in failure.reason


def test_offline_without_the_file_cached_keeps_the_json_values(
    fake_http: FakeTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _metadata()
    fake_http.reply(
        url="/simple/demo/",
        json=_page(_file(_WHEEL, core_metadata={"sha256": _sha256(text)})),
    )
    package = _package()

    def refuse(url: str) -> None:
        raise http.OfflineError(url)

    monkeypatch.setattr(http, "_refuse_offline", refuse)
    assert attach_release_metadata(package).core_metadata == package.core_metadata


def test_a_relative_file_url_is_resolved_against_the_project_page(
    fake_http: FakeTransport,
) -> None:
    text = _metadata()
    entry = _file(_WHEEL, core_metadata={"sha256": _sha256(text)})
    entry["url"] = "../../files/demo-1.0-py3-none-any.whl"
    fake_http.reply(url="/simple/demo/", json=_page(entry))
    fake_http.reply(url=".metadata", text=text)
    meta = attach_release_metadata(_package()).core_metadata
    assert meta is not None
    assert meta.source == "release_metadata"
    assert str(fake_http.requests[-1].url) == (
        "https://pypi.org/files/demo-1.0-py3-none-any.whl.metadata"
    )


def test_a_failed_project_page_is_reported(fake_http: FakeTransport) -> None:
    fake_http.reply(url="/simple/demo/", status=500)
    result = attach_release_metadata(_package())
    assert [f.source for f in result.enrichment_failures] == [SOURCE_NAME]
