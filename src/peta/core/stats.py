"""Download and dependent count lookups (best-effort enrichment)."""

from __future__ import annotations

import os
from typing import Required, TypedDict, cast

import httpx

from peta.core.remote import DEFAULT_TIMEOUT

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

# Best-effort errors swallowed to ``None``/``0`` (network, or a
# malformed/partial body). Kept as a named tuple so ``ruff format`` cannot
# rewrite a parenthesized ``except (...)`` into invalid ``except A, B:`` syntax.
_BEST_EFFORT_ERRORS = (
    httpx.RequestError,
    AttributeError,
    KeyError,
    TypeError,
    ValueError,
)


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


def _as_int(value: object) -> int | None:
    """Validate a decoded count value.

    ``bool`` is rejected even though it is a ``int`` subclass, since a JSON
    ``true``/``false`` is not a meaningful count.

    Returns:
        ``value`` if it is a genuine ``int``, else ``None``.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _fetch_pypistats(name: str) -> PypiStatsResponse:
    response = httpx.get(f"{PYPISTATS_URL}/{name}/recent", timeout=DEFAULT_TIMEOUT)
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        msg = f"pypistats returned HTTP {response.status_code}"
        raise ValueError(msg)
    return cast("PypiStatsResponse", response.json())


def get_download_count(name: str) -> int | None:
    """Look up a package's last-month download count on pypistats.org.

    This is best-effort enrichment: any network failure, non-200 response,
    or malformed body results in ``None`` rather than raising.

    Args:
        name: Package name to query (assumed to be a PyPI package).

    Returns:
        The last-month download count, or ``None`` on any failure.
    """
    try:
        data = _fetch_pypistats(name)
        return _as_int(data["data"]["last_month"])
    except _BEST_EFFORT_ERRORS:
        return None


def libraries_io_api_key() -> str | None:
    """Read the libraries.io API key from the environment.

    Returns:
        The ``LIBRARIES_IO_API_KEY`` value, or ``None`` if unset or empty.
    """
    return os.environ.get("LIBRARIES_IO_API_KEY") or None


def _fetch_libraries_io(name: str, api_key: str) -> LibrariesIoResponse:
    response = httpx.get(
        f"{LIBRARIES_IO_URL}/{name}",
        params={"api_key": api_key},
        timeout=DEFAULT_TIMEOUT,
    )
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        msg = f"libraries.io returned HTTP {response.status_code}"
        raise ValueError(msg)
    return cast("LibrariesIoResponse", response.json())


def get_dependent_count(name: str, *, api_key: str | None) -> int | None:
    """Look up a package's dependent count on libraries.io.

    This is best-effort enrichment: any network failure, non-200 response,
    or malformed body results in ``None`` rather than raising. No request is
    made at all when no API key is available.

    Args:
        name: Package name to query (assumed to be a PyPI package).
        api_key: The libraries.io API key, or ``None`` to skip the lookup.

    Returns:
        The dependent count, or ``None`` on any failure or missing key.
    """
    if not api_key:
        return None
    try:
        data = _fetch_libraries_io(name, api_key)
        return _as_int(data["dependents_count"])
    except _BEST_EFFORT_ERRORS:
        return None
