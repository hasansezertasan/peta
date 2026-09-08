"""PEP 691 Simple Repository API client for version and file discovery.

The PyPI JSON API's ``releases`` mapping is deprecated; PyPI recommends the
Simple Repository API (PEP 503 / PEP 691) for distribution and version
discovery.  This module requests the JSON representation of a project page
(``/simple/<project>/``) and returns a validated, typed view of the response
that carries the version list and per-file metadata future consumers need.

Only transport and validation live here.  How a command uses the page — which
fields it reads, how it orders versions — stays with the caller.
"""

from __future__ import annotations

import contextlib
import operator
from typing import TYPE_CHECKING, Required, TypedDict, cast

import httpx
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from peta.core import cache, http
from peta.core.remote import NetworkError
from peta.core.validation import (
    ResponseValidationError,
    expect_list,
    expect_mapping,
    expect_string,
    optional_string,
)

if TYPE_CHECKING:
    from peta.core.cache import Provenance

__all__ = ["PYPI_SIMPLE_URL", "IndexFile", "ProjectPage", "get_project_page"]

PYPI_SIMPLE_URL = "https://pypi.org/simple"

PEP691_ACCEPT = "application/vnd.pypi.simple.v1+json"

_SOURCE = "Simple API"


class IndexFile(TypedDict, total=False):
    """One distribution file from the Simple API project page."""

    filename: Required[str]
    url: Required[str]
    hashes: dict[str, str]
    requires_python: str | None
    yanked: str | bool
    size: int | None
    upload_time: str | None
    core_metadata: dict[str, str] | bool
    provenance: str | None


class ProjectPage(TypedDict):
    """The validated subset of a PEP 691 project page peta consumes."""

    name: str
    versions: list[str]
    files: list[IndexFile]


def _validate_hashes(value: object, path: str) -> dict[str, str]:
    if value is None:
        return {}
    mapping = expect_mapping(value, source=_SOURCE, path=path)
    for k, v in mapping.items():
        if not isinstance(v, str):
            msg = _SOURCE
            raise ResponseValidationError(msg, f"{path}.{k}", "a string")
    return cast("dict[str, str]", mapping)


def _validate_file_scalars(
    raw: dict[str, object], path: str
) -> tuple[str | None, str | bool, int | None, str | None]:
    requires_python = raw.get("requires-python")
    if requires_python is not None and not isinstance(requires_python, str):
        msg = _SOURCE
        raise ResponseValidationError(
            msg, f"{path}.requires-python", "a string or null"
        )

    raw_yanked = raw.get("yanked", False)
    if not isinstance(raw_yanked, (str, bool)):
        msg = _SOURCE
        raise ResponseValidationError(msg, f"{path}.yanked", "a string or boolean")
    yanked: str | bool = raw_yanked

    size = raw.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool)):
        msg = _SOURCE
        raise ResponseValidationError(msg, f"{path}.size", "an integer or null")

    upload_time = raw.get("upload-time")
    if upload_time is not None and not isinstance(upload_time, str):
        msg = _SOURCE
        raise ResponseValidationError(msg, f"{path}.upload-time", "a string or null")

    return (requires_python, yanked, size, upload_time)


def _validate_file(value: object, index: int) -> IndexFile:
    path = f"$.files[{index}]"
    raw = expect_mapping(value, source=_SOURCE, path=path)
    filename = expect_string(
        raw.get("filename"), source=_SOURCE, path=f"{path}.filename"
    )
    url = expect_string(raw.get("url"), source=_SOURCE, path=f"{path}.url")
    hashes = _validate_hashes(raw.get("hashes"), f"{path}.hashes")
    requires_python, yanked, size, upload_time = _validate_file_scalars(raw, path)
    provenance = optional_string(raw, "provenance", source=_SOURCE, path=path)

    result: IndexFile = {"filename": filename, "url": url, "hashes": hashes}
    result["requires_python"] = requires_python
    result["yanked"] = yanked
    result["size"] = size
    result["upload_time"] = upload_time
    result["provenance"] = provenance

    core_metadata = raw.get("core-metadata")
    if core_metadata is None:
        core_metadata = raw.get("dist-info-metadata")
    if isinstance(core_metadata, bool):
        result["core_metadata"] = core_metadata
    elif isinstance(core_metadata, dict):
        result["core_metadata"] = _validate_hashes(
            cast("object", core_metadata), f"{path}.core-metadata"
        )

    return result


def _validate_response(body: object) -> ProjectPage:
    root = expect_mapping(body, source=_SOURCE, path="$")
    name = expect_string(root.get("name"), source=_SOURCE, path="$.name")
    raw_versions = expect_list(root.get("versions"), source=_SOURCE, path="$.versions")
    versions: list[str] = [
        expect_string(v, source=_SOURCE, path=f"$.versions[{i}]")
        for i, v in enumerate(raw_versions)
    ]
    raw_files = root.get("files")
    files: list[IndexFile] = []
    if raw_files is not None:
        for i, f in enumerate(expect_list(raw_files, source=_SOURCE, path="$.files")):
            files.append(_validate_file(f, i))
    return ProjectPage(name=name, versions=versions, files=files)


def _version_from_filename(filename: str) -> Version | None:
    """Extract a parsed version from a distribution filename.

    Returns:
        The parsed :class:`Version`, or ``None`` for unrecognized formats.
    """
    if filename.endswith(".whl"):
        with contextlib.suppress(InvalidWheelFilename):
            _, version, _, _ = parse_wheel_filename(filename)
            return version
        return None
    if filename.endswith((".tar.gz", ".zip")):
        with contextlib.suppress(InvalidSdistFilename):
            _, version = parse_sdist_filename(filename)
            return version
        return None
    return None


def _version_originals(versions: list[str]) -> dict[Version, str]:
    """Map parsed versions to their original strings from the versions list.

    Returns:
        A lookup from :class:`Version` to the original version string.
    """
    result: dict[Version, str] = {}
    for v in versions:
        with contextlib.suppress(InvalidVersion):
            result[Version(v)] = v
    return result


def _resolve_upload_date(
    f: IndexFile, originals: dict[Version, str]
) -> tuple[str, str] | None:
    raw = f.get("upload_time")
    if not raw:
        return None
    parsed = _version_from_filename(f["filename"])
    if parsed is None:
        return None
    original = originals.get(parsed)
    if original is None:
        return None
    return original, raw[:10]


def upload_times(page: ProjectPage) -> dict[str, str]:
    """Map each version to its earliest file upload date (YYYY-MM-DD).

    Files are matched to versions via their filename.  Matching uses parsed
    :class:`~packaging.version.Version` equality so that ``"1.0"`` and
    ``"1.0.0"`` resolve to the same version.  Versions whose files lack an
    ``upload-time`` or whose filenames cannot be parsed are omitted.

    Returns:
        A mapping from the original version string to ``YYYY-MM-DD`` date.
    """
    originals = _version_originals(page["versions"])
    earliest: dict[str, str] = {}
    for f in page["files"]:
        resolved = _resolve_upload_date(f, originals)
        if resolved is None:
            continue
        version, date = resolved
        if date < earliest.get(version, "\xff"):
            earliest[version] = date
    return earliest


def sorted_versions(versions: list[str]) -> list[str]:
    """Return version strings newest-first, tolerating non-PEP-440 keys.

    Returns:
        PEP 440 versions newest-first, then non-PEP-440 keys sorted.
    """
    valid: list[tuple[Version, str]] = []
    invalid: list[str] = []
    for ver in versions:
        try:
            valid.append((Version(ver), ver))
        except InvalidVersion:
            invalid.append(ver)
    valid.sort(key=operator.itemgetter(0), reverse=True)
    return [ver for _, ver in valid] + sorted(invalid, reverse=True)


def _fetch_page(name: str, base_url: str) -> tuple[httpx.Response, http.Fetched]:
    canonical = canonicalize_name(name)
    url = f"{base_url.rstrip('/')}/{canonical}/"
    try:
        fetched = http.get(
            url, headers={"accept": PEP691_ACCEPT}, ttl=cache.LATEST, scope="index"
        )
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc
    return fetched.response, fetched


def get_project_page(
    name: str, *, base_url: str = PYPI_SIMPLE_URL
) -> tuple[ProjectPage, Provenance]:
    """Fetch the Simple API project page for a package.

    Args:
        name: Package name (any spelling — normalized before requesting).
        base_url: The index base URL, so alternate indexes work without
            another redesign.

    Returns:
        The validated project page, and where it came from.

    Raises:
        NetworkError: On transport failures, non-success statuses, or a
            malformed response body.
    """
    response, fetched = _fetch_page(name, base_url)
    canonical = canonicalize_name(name)

    if response.status_code == 404:  # ruff: ignore[magic-value-comparison]
        return ProjectPage(name=canonical, versions=[], files=[]), fetched.provenance

    try:
        _ = response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        msg = f"Simple API returned HTTP {exc.response.status_code}"
        raise NetworkError(msg) from exc

    try:
        body = cast("object", response.json())
    except ValueError as exc:
        msg = "malformed response from Simple API"
        raise NetworkError(msg) from exc

    try:
        page = _validate_response(body)
    except ResponseValidationError as exc:
        msg = f"malformed response from Simple API: {exc}"
        raise NetworkError(msg) from exc

    http.keep(fetched)
    return page, fetched.provenance
