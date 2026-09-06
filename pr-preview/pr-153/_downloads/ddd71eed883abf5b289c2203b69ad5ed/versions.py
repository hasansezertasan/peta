"""The ``peta versions`` command."""

from __future__ import annotations

import operator
from typing import TYPE_CHECKING, cast

import httpx
import typer
from packaging.version import InvalidVersion, Version

from peta.cli.output.render import render_versions
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.output import utc_now
from peta.core.remote import DEFAULT_TIMEOUT, PYPI_BASE_URL, NetworkError
from peta.core.validation import (
    ResponseValidationError,
    expect_list,
    expect_mapping,
    optional_string,
)

if TYPE_CHECKING:
    from peta.core.remote import PyPIReleaseFile

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


def _extract_releases(body: object) -> dict[str, list[PyPIReleaseFile]]:
    """Validate and pull the ``releases`` mapping out of a decoded PyPI body.

    Returns:
        The validated release mapping.

    Raises:
        NetworkError: If the body, or its ``releases`` field, is not a dict.
    """
    try:
        mapping = expect_mapping(body, source="PyPI", path="$")
        releases = expect_mapping(
            mapping.get("releases"), source="PyPI", path="$.releases"
        )
        return {ver: _clean_files(raw, ver) for ver, raw in releases.items()}
    except ResponseValidationError as exc:
        msg = f"malformed response from PyPI: {exc}"
        raise NetworkError(msg) from exc


def _clean_files(raw: object, version: str) -> list[PyPIReleaseFile]:
    """Validate one release's file list.

    Returns:
        The validated list of release-file mappings.
    """
    path = f"$.releases.{version}"
    items = expect_list(raw, source="PyPI", path=path)
    files: list[dict[str, object]] = []
    for index, item in enumerate(items):
        file_path = f"{path}[{index}]"
        release_file = expect_mapping(item, source="PyPI", path=file_path)
        _ = optional_string(release_file, "upload_time", source="PyPI", path=file_path)
        files.append(release_file)
    return cast("list[PyPIReleaseFile]", cast("object", files))


def _decode_body(response: httpx.Response) -> object:
    """Decode a JSON response body, mapping a decode failure to NetworkError.

    Returns:
        The decoded body as an untyped object.

    Raises:
        NetworkError: If the body is not valid JSON.
    """
    try:
        return cast("object", response.json())
    except ValueError as exc:  # includes json.JSONDecodeError
        msg = "malformed response from PyPI"
        raise NetworkError(msg) from exc


def get_versions(name: str) -> list[dict[str, str]]:
    """Fetch all published versions for a package from PyPI.

    Returns:
        A list of ``{"version", "upload_time"}`` dicts, newest first; empty
        if the package is not found (HTTP 404).

    Raises:
        NetworkError: If the request fails, returns a non-success status, or
            the decoded body is malformed (not a dict, or ``releases`` is not
            a dict).
    """
    url = f"{PYPI_BASE_URL}/{name}/json"
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # ruff: ignore[magic-value-comparison]
        return []

    try:
        _ = response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        msg = f"PyPI returned HTTP {exc.response.status_code}"
        raise NetworkError(msg) from exc

    # The PyPI JSON API is untyped and its shape is not guaranteed, so
    # validate the decoded body before casting into our typed view.
    releases = _extract_releases(_decode_body(response))
    result: list[dict[str, str]] = []
    for ver in _sorted_version_keys(releases):
        files = releases[ver]
        raw_time: object = files[0].get("upload_time", "") if files else ""
        upload_time = raw_time[:10] if isinstance(raw_time, str) else ""
        result.append({"version": ver, "upload_time": upload_time})
    return result


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
        vers = remote_get_versions(package)
        retrieved_at = utc_now()
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
        retrieved_at=retrieved_at,
    )
    typer.echo(rendered)
