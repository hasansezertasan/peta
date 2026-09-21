"""The ``peta versions`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_versions
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core import http
from peta.core.index import get_project_page, sorted_versions, upload_times
from peta.core.remote import NetworkError

if TYPE_CHECKING:
    from peta.core.cache import Provenance

__all__ = ["get_versions", "versions"]


def get_versions(name: str) -> tuple[list[dict[str, str]], Provenance]:
    """Fetch all published versions for a package from the Simple API.

    Returns:
        A list of ``{"version", "upload_time"}`` dicts newest first, and where
        the listing came from; the list is empty if the package is not found
        (HTTP 404).
    """
    page, provenance = get_project_page(name)
    if not page["versions"]:
        return [], provenance
    dates = upload_times(page)
    result: list[dict[str, str]] = [
        {"version": ver, "upload_time": dates.get(ver, "")}
        for ver in sorted_versions(page["versions"])
    ]
    return result, provenance


# Patch target used by tests.
remote_get_versions = get_versions


def versions(
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat | None = None,
    limit: int = 20,
    color: bool = False,
) -> None:
    """Show published versions of a package from PyPI."""
    arguments: dict[str, object] = {"package": package, "limit": limit}
    selected = resolve_or_fail("versions", arguments, output_format, use_json=use_json)
    try:
        vers, provenance = remote_get_versions(package)
    except http.OfflineError as exc:
        fail(
            "versions",
            arguments=arguments,
            code="offline_unavailable",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    except NetworkError as exc:
        fail(
            "versions",
            arguments=arguments,
            code="network_error",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    if not vers:
        fail(
            "versions",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found on PyPI.",
            output_format=selected,
            exit_code=1,
            source="pypi",
        )
    shown = vers[:limit]
    rendered = render_versions(
        selected,
        package,
        shown,
        arguments=arguments,
        color=color,
        retrieved_at=provenance.retrieved_at,
        freshness=provenance.freshness,
    )
    typer.echo(rendered)
