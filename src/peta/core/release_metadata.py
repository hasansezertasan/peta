"""Core Metadata read from a release's PEP 658 ``.metadata`` file.

PyPI's JSON API serves only some Core Metadata fields. When the Simple API
advertises the release's ``METADATA`` file, that file is the same one an
installed copy carries, so reading it keeps the remote and installed models
aligned.

The file is fetched from an address the index chose, so nothing in it is used
until its bytes match the hash the index advertised. A file that fails any
check is a failure, never data, and the JSON API's values stay in place.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import itertools
import re
from dataclasses import dataclass
from email.parser import Parser
from typing import TYPE_CHECKING

import httpx
from packaging.utils import canonicalize_name

from peta.core import http, validation
from peta.core.index import PYPI_SIMPLE_URL, files_for_version, get_project_page
from peta.core.metadata import core_metadata_from_headers
from peta.core.models import EnrichmentFailure
from peta.core.output import SourceRecord, utc_now
from peta.core.remote import NetworkError

if TYPE_CHECKING:
    from email.message import Message

    from peta.core.index import IndexFile
    from peta.core.models import CoreMetadata, PackageInfo

__all__ = ["SOURCE_NAME", "attach_release_metadata"]

SOURCE_NAME = "pypi-metadata"
"""The provenance name of the ``.metadata`` file, apart from PyPI's JSON API."""

_FIELD = "result.core_metadata"
_ALGORITHMS = ("sha512", "sha384", "sha256")
"""Digest algorithms trusted to authenticate a file, strongest first.

``md5`` and ``sha1`` are never accepted: a hash that can be forged proves
nothing about who wrote the bytes.
"""
_OK = 200
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
"""A line ending as the email parser reads it: CRLF, a lone CR, or LF."""
_BLANK_LINE = re.compile(r"(?>\r\n|\r|\n)(?>\r\n|\r|\n)")
"""The empty line ending the header block, matched atomically so the CRLF of
one line is never split into the two breaks of a blank one."""


class ReleaseMetadataError(Exception):
    """Raised when an advertised ``.metadata`` file cannot be trusted or read."""


@dataclass(frozen=True)
class _Advertised:
    """A ``.metadata`` file the index advertises, and the hash it must match."""

    url: str
    algorithm: str
    digest: str


def _strongest_digest(hashes: dict[str, str]) -> tuple[str, str] | None:
    for algorithm in _ALGORITHMS:
        digest = hashes.get(algorithm)
        if digest:
            return algorithm, digest.lower()
    return None


def _advertised(entry: IndexFile, page_url: httpx.URL) -> _Advertised | None:
    """Read what one file entry advertises for its ``.metadata``.

    An advertisement without a usable hash is passed over, not trusted:
    there would be nothing to verify the bytes against.

    Returns:
        The file's address and hash, or ``None`` when it offers neither.
    """
    hashes = entry.get("core_metadata")
    if not isinstance(hashes, dict):
        return None
    found = _strongest_digest(hashes)
    if found is None:
        return None
    try:
        # PEP 691 allows a file URL relative to the project page.
        base = page_url.join(entry["url"])
    except httpx.InvalidURL:
        return None
    # PEP 658 appends the suffix to the file's path, ahead of any fragment.
    url = base.copy_with(path=f"{base.path}.metadata", fragment=None)
    return _Advertised(str(url), *found)


def _choose(files: list[IndexFile], page_url: httpx.URL) -> _Advertised | None:
    """Pick the file to read: a wheel's metadata before an sdist's.

    Every file of a release declares the same metadata, so the first usable
    advertisement answers; the stable sort keeps the index's own order within
    each kind.

    Returns:
        The chosen advertisement, or ``None`` when no file offers one.
    """
    for entry in sorted(files, key=lambda f: not f["filename"].endswith(".whl")):
        advertised = _advertised(entry, page_url)
        if advertised is not None:
            return advertised
    return None


def _download(advertised: _Advertised) -> bytes:
    """Fetch the file and check it against the advertised hash.

    Never cached: the cache stores JSON only, and the file is small next to
    the project page that names it.

    Returns:
        The file's bytes, once they match the hash.

    Raises:
        ReleaseMetadataError: If the request fails, or the bytes do not match.
    """
    try:
        response = http.get(advertised.url).response
    except httpx.RequestError as exc:
        raise ReleaseMetadataError(str(exc)) from exc
    if response.status_code != _OK:
        msg = f"{advertised.url} returned HTTP {response.status_code}"
        raise ReleaseMetadataError(msg)
    content = response.content
    actual = hashlib.new(advertised.algorithm, content).hexdigest()
    if not hmac.compare_digest(actual.encode(), advertised.digest.encode()):
        msg = (
            f"{advertised.url} does not match its advertised "
            f"{advertised.algorithm} hash"
        )
        raise ReleaseMetadataError(msg)
    return content


def _header_block(text: str) -> str:
    """Cut a file down to its headers, bounding their count before parsing.

    Counted on the raw text because the parser builds every header it is
    given: millions of tiny ones fit under the body limit and would cost far
    more as objects than as bytes.

    Returns:
        The text up to the first blank line.

    Raises:
        ReleaseMetadataError: If the block has too many lines.
    """
    end = _BLANK_LINE.search(text)
    block = text if end is None else text[: end.start()]
    # Stops counting at the limit instead of listing every break, so the
    # check itself costs nothing proportional to the file.
    breaks = _LINE_BREAK.finditer(block)
    if next(itertools.islice(breaks, validation.MAX_COLLECTION_ITEMS - 1, None), None):
        msg = f"metadata file has more than {validation.MAX_COLLECTION_ITEMS:,} headers"
        raise ReleaseMetadataError(msg)
    return block


def _check_headers(headers: Message) -> None:
    """Refuse headers the parser flagged, oversized ones, or missing identity.

    Raises:
        ReleaseMetadataError: If the file is malformed or breaks a limit.
    """
    if headers.defects:
        msg = f"metadata file has a malformed header: {headers.defects[0]}"
        raise ReleaseMetadataError(msg)
    if any(
        len(str(value)) > validation.MAX_STRING_LENGTH for value in headers.values()
    ):
        limit = validation.MAX_STRING_LENGTH
        msg = f"metadata file has a header over {limit:,} characters"
        raise ReleaseMetadataError(msg)
    for required in ("Metadata-Version", "Name", "Version"):
        if required not in headers:
            msg = f"metadata file declares no {required}"
            raise ReleaseMetadataError(msg)


def _parse(content: bytes) -> CoreMetadata:
    """Read the headers of a ``METADATA`` file, within the response limits.

    Only the header block is parsed; the long description after it is never
    read. A file with more headers than a collection may hold, or a value
    longer than a metadata string may be, is refused like an oversized JSON
    document.

    Returns:
        The declared metadata.

    Raises:
        ReleaseMetadataError: If the file is not UTF-8, breaks a limit, or
            names no ``Metadata-Version``.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "metadata file is not valid UTF-8"
        raise ReleaseMetadataError(msg) from exc
    headers = Parser().parsestr(_header_block(text), headersonly=True)
    _check_headers(headers)
    return core_metadata_from_headers(headers, source="release_metadata")


def _failed(pkg: PackageInfo, reason: str) -> PackageInfo:
    """Record a refused file without touching the JSON API's values.

    Returns:
        The package, carrying a failure and a failed source record.
    """
    failure = EnrichmentFailure(source=SOURCE_NAME, reason=reason, field=_FIELD)
    record = SourceRecord(
        name=SOURCE_NAME,
        state="failed",
        target=pkg.name,
        retrieved_at=utc_now(),
        reason=failure.reason,
        fields=[_FIELD],
    )
    return dataclasses.replace(
        pkg,
        enrichment_failures=[*pkg.enrichment_failures, failure],
        enrichment_sources=[*pkg.enrichment_sources, record],
    )


def _verified(pkg: PackageInfo, advertised: _Advertised) -> PackageInfo:
    """Replace the package's metadata with the verified file's.

    Returns:
        The package with release metadata, or a failed one if the file is refused.
    """
    try:
        metadata = _parse(_download(advertised))
    except ReleaseMetadataError as exc:
        return _failed(pkg, str(exc))
    record = SourceRecord(
        name=SOURCE_NAME,
        state="success",
        target=pkg.name,
        retrieved_at=utc_now(),
        freshness="live",
        fields=[_FIELD],
    )
    return dataclasses.replace(
        pkg,
        core_metadata=metadata,
        enrichment_sources=[*pkg.enrichment_sources, record],
    )


def attach_release_metadata(pkg: PackageInfo) -> PackageInfo:
    """Replace a remote package's Core Metadata with its release's ``METADATA``.

    Without an advertised file the package is returned unchanged, so the JSON
    API's values stand and nothing missing is inferred. Offline, or when the
    project page cannot be read, the same applies: the lookup is an upgrade,
    not a requirement of ``peta info``. A file that is advertised but refused
    — a hash mismatch, a malformed or oversized body — is reported as a failed
    source.

    Returns:
        The package, with release metadata when the index offered a verified file.
    """
    try:
        page, _ = get_project_page(pkg.name)
    except http.OfflineError:
        return pkg
    except NetworkError as exc:
        return _failed(pkg, f"could not read the project page: {exc}")
    page_url = httpx.URL(f"{PYPI_SIMPLE_URL}/{canonicalize_name(pkg.name)}/")
    advertised = _choose(files_for_version(page, pkg.version), page_url)
    if advertised is None:
        return pkg
    try:
        return _verified(pkg, advertised)
    except http.OfflineError:
        return pkg
