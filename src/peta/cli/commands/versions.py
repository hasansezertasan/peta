"""The ``peta versions`` command."""

from __future__ import annotations

from typing import Any

import httpx
import typer
from packaging.version import Version

from peta.core.remote import DEFAULT_TIMEOUT, PYPI_BASE_URL, NetworkError
from peta.output.json import format_versions as json_format
from peta.output.tables import render_versions as rich_format


def get_versions(name: str) -> list[dict[str, str]]:
    """Fetch all published versions for a package from PyPI."""
    url = f"{PYPI_BASE_URL}/{name}/json"
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # noqa: PLR2004
        return []

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"PyPI returned HTTP {exc.response.status_code}") from exc

    data: dict[str, Any] = response.json()
    releases: dict[str, list[dict[str, Any]]] = data.get("releases", {})
    result: list[dict[str, str]] = []
    for ver, files in sorted(releases.items(), key=lambda kv: Version(kv[0]), reverse=True):
        upload_time = files[0].get("upload_time", "")[:10] if files else ""
        result.append({"version": ver, "upload_time": upload_time})
    return result


# Patch target used by tests.
remote_get_versions = get_versions


def versions(package: str, *, use_json: bool = False, limit: int = 20) -> None:
    """Show published versions of a package from PyPI."""
    try:
        vers = remote_get_versions(package)
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    if not vers:
        typer.echo(f"Package '{package}' not found on PyPI.", err=True)
        raise typer.Exit(code=1) from None
    shown = vers[:limit]
    typer.echo(json_format(package, shown) if use_json else rich_format(package, shown))
