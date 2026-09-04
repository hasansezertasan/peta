"""Download and dependent count lookups (best-effort enrichment)."""

from __future__ import annotations

import os
from typing import Required, TypedDict, cast

import httpx

from peta.core.remote import DEFAULT_TIMEOUT
from peta.core.validation import (
    EnrichmentError,
    ResponseValidationError,
    expect_int,
    expect_mapping,
)

__all__ = [
    "LIBRARIES_IO_URL",
    "PYPISTATS_URL",
    "LibrariesIoResponse",
    "PypiStatsData",
    "PypiStatsResponse",
    "get_dependent_count",
    "get_download_count",
    "libraries_io_api_key",
]


PYPISTATS_URL = "https://pypistats.org/api/packages"
LIBRARIES_IO_URL = "https://libraries.io/api/pypi"
PYPISTATS_SOURCE = "pypistats"
LIBRARIES_IO_SOURCE = "libraries.io"


# Both pypistats.org and libraries.io are untyped from Python's perspective
# (``response.json()`` returns ``Any``). These ``TypedDict``\ s describe only
# the fields peta reads, so the decoded body can be brought into the typed
# world with a single ``typing.cast`` at each ``.json()`` boundary.
class PypiStatsData(TypedDict, total=False):
    """The ``data`` object of a pypistats.org "recent" response."""

    last_month: Required[int]


class PypiStatsResponse(TypedDict, total=False):
    """The top-level pypistats.org "recent" JSON payload."""

    data: Required[PypiStatsData]


class LibrariesIoResponse(TypedDict, total=False):
    """The fields peta reads from a libraries.io project JSON payload."""

    dependents_count: Required[int]


def _decode(response: httpx.Response, source: str) -> object:
    try:
        return cast("object", response.json())
    except ValueError as exc:
        raise EnrichmentError(source, "invalid JSON") from exc


def _fetch_pypistats(name: str) -> int:
    try:
        response = httpx.get(f"{PYPISTATS_URL}/{name}/recent", timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise EnrichmentError(PYPISTATS_SOURCE, str(exc)) from exc
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        raise EnrichmentError(PYPISTATS_SOURCE, f"HTTP {response.status_code}")
    try:
        root = expect_mapping(
            _decode(response, PYPISTATS_SOURCE), source=PYPISTATS_SOURCE, path="$"
        )
        data = expect_mapping(root.get("data"), source=PYPISTATS_SOURCE, path="$.data")
        return expect_int(
            data.get("last_month"), source=PYPISTATS_SOURCE, path="$.data.last_month"
        )
    except ResponseValidationError as exc:
        raise EnrichmentError(PYPISTATS_SOURCE, f"malformed response: {exc}") from exc


def get_download_count(name: str) -> int | None:
    """Look up a package's last-month download count on pypistats.org.

    The enrichment coordinator catches source-specific failures so they remain
    non-fatal while still being visible to users.

    Args:
        name: Package name to query (assumed to be a PyPI package).

    Returns:
        The last-month download count.

    """
    return _fetch_pypistats(name)


def libraries_io_api_key() -> str | None:
    """Read the libraries.io API key from the environment.

    Returns:
        The ``LIBRARIES_IO_API_KEY`` value, or ``None`` if unset or empty.
    """
    return os.environ.get("LIBRARIES_IO_API_KEY") or None


def _fetch_libraries_io(name: str, api_key: str) -> int:
    try:
        response = httpx.get(
            f"{LIBRARIES_IO_URL}/{name}",
            params={"api_key": api_key},
            timeout=DEFAULT_TIMEOUT,
        )
    except httpx.RequestError as exc:
        raise EnrichmentError(LIBRARIES_IO_SOURCE, str(exc)) from exc
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        raise EnrichmentError(LIBRARIES_IO_SOURCE, f"HTTP {response.status_code}")
    try:
        root = expect_mapping(
            _decode(response, LIBRARIES_IO_SOURCE), source=LIBRARIES_IO_SOURCE, path="$"
        )
        return expect_int(
            root.get("dependents_count"),
            source=LIBRARIES_IO_SOURCE,
            path="$.dependents_count",
        )
    except ResponseValidationError as exc:
        raise EnrichmentError(
            LIBRARIES_IO_SOURCE, f"malformed response: {exc}"
        ) from exc


def get_dependent_count(name: str, *, api_key: str | None) -> int | None:
    """Look up a package's dependent count on libraries.io.

    The enrichment coordinator catches source-specific failures so they remain
    non-fatal while still being visible to users. No request is made at all
    when no API key is available.

    Args:
        name: Package name to query (assumed to be a PyPI package).
        api_key: The libraries.io API key, or ``None`` to skip the lookup.

    Returns:
        The dependent count, or ``None`` when no API key is configured.

    """
    if not api_key:
        return None
    return _fetch_libraries_io(name, api_key)
