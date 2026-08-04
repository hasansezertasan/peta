"""The ``peta versions`` command."""

from __future__ import annotations

import operator
from typing import TYPE_CHECKING, cast

import httpx
import typer
from packaging.version import InvalidVersion, Version

from peta.core.remote import DEFAULT_TIMEOUT, PYPI_BASE_URL, NetworkError
from peta.output.json import format_versions as json_format
from peta.output.tables import render_versions as rich_format

if TYPE_CHECKING:
    from peta.core.remote import PyPIReleaseFile, PyPIResponse

__all__ = ["get_versions", "versions"]


def _sorted_version_keys(releases: dict[str, list[PyPIReleaseFile]]) -> list[str]:
    """Return release keys newest-first, tolerating non-PEP-440 keys.

    ``packaging.version.Version`` raises ``InvalidVersion`` on legacy keys that
    PyPI still serves, so parse defensively: PEP 440 versions sort newest-first,
    and any unparsable keys are kept (sorted after) rather than letting one bad
    key abort the whole listing with a traceback.

    Returns:
        Release keys, PEP 440 versions newest-first, then non-PEP-440 keys.
    """
    valid: list[tuple[Version, str]] = []
    invalid: list[str] = []
    for ver in releases:
        try:
            valid.append((Version(ver), ver))
        except InvalidVersion:
            invalid.append(ver)
    valid.sort(key=operator.itemgetter(0), reverse=True)
    return [ver for _, ver in valid] + sorted(invalid, reverse=True)


def get_versions(name: str) -> list[dict[str, str]]:
    """Fetch all published versions for a package from PyPI.

    Returns:
        A list of ``{"version", "upload_time"}`` dicts, newest first; empty
        if the package is not found (HTTP 404).

    Raises:
        NetworkError: If the request fails or returns a non-success status.
    """
    url = f"{PYPI_BASE_URL}/{name}/json"
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # noqa: PLR2004
        return []

    try:
        _ = response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        msg = f"PyPI returned HTTP {exc.response.status_code}"
        raise NetworkError(msg) from exc

    # Single typed boundary: the PyPI JSON API is untyped, so cast the decoded
    # body into our TypedDict view of the fields we actually read.
    data: PyPIResponse = cast("PyPIResponse", response.json())
    releases: dict[str, list[PyPIReleaseFile]] = data.get("releases", {})
    result: list[dict[str, str]] = []
    for ver in _sorted_version_keys(releases):
        files = releases[ver]
        upload_time = files[0].get("upload_time", "")[:10] if files else ""
        result.append({"version": ver, "upload_time": upload_time})
    return result


# Patch target used by tests.
remote_get_versions = get_versions


def versions(
    package: str, *, use_json: bool = False, limit: int = 20, color: bool = False
) -> None:
    """Show published versions of a package from PyPI.

    Raises:
        Exit: With code 2 on network failure, or code 1 if the package is absent.
    """
    try:
        vers = remote_get_versions(package)
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    if not vers:
        typer.echo(f"Package '{package}' not found on PyPI.", err=True)
        raise typer.Exit(code=1) from None
    shown = vers[:limit]
    typer.echo(
        json_format(package, shown)
        if use_json
        else rich_format(package, shown, color=color)
    )
