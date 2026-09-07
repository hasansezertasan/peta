"""PyPI JSON API client for remote package metadata."""

from __future__ import annotations

from typing import Literal, Required, TypedDict, cast

import httpx

from peta.core.models import PackageInfo, Vulnerability
from peta.core.output import utc_now
from peta.core.validation import (
    ResponseValidationError,
    expect_list,
    expect_mapping,
    expect_string,
    optional_string,
    optional_string_list,
    optional_string_mapping,
)

__all__ = [
    "NetworkError",
    "PackageNotFoundError",
    "PyPIInfo",
    "PyPIReleaseFile",
    "PyPIResponse",
    "PyPIVulnerability",
    "get_package",
]


PYPI_BASE_URL = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10.0


# The PyPI JSON API is untyped from Python's perspective (``response.json()``
# returns ``Any``). These ``TypedDict``\ s describe only the fields peta reads,
# so the decoded body can be brought into the typed world with a single
# ``typing.cast`` at each ``.json()`` boundary. Fields peta always indexes
# directly are ``Required``; everything read via ``.get(...)`` is optional
# (``total=False``), mirroring the fact that PyPI does not guarantee any key.
class PyPIInfo(TypedDict, total=False):
    """The ``info`` object of a PyPI package payload."""

    name: Required[str]
    version: Required[str]
    summary: str | None
    author: str | None
    author_email: str | None
    maintainer: str | None
    license: str | None
    license_expression: str | None
    requires_python: str | None
    home_page: str | None
    project_urls: dict[str, str] | None
    requires_dist: list[str] | None
    classifiers: list[str]
    keywords: str | None


class PyPIVulnerability(TypedDict, total=False):
    """A single entry of the ``vulnerabilities`` array."""

    id: Required[str]
    aliases: list[str]
    summary: str
    fixed_in: list[str]


class PyPIReleaseFile(TypedDict, total=False):
    """A single distribution file within a release entry."""

    upload_time: str


class PyPIResponse(TypedDict, total=False):
    """The top-level PyPI JSON payload for a package."""

    info: Required[PyPIInfo]
    vulnerabilities: list[PyPIVulnerability]
    releases: dict[str, list[PyPIReleaseFile]]


class PackageNotFoundError(Exception):
    """Raised when a package is not found on PyPI."""

    def __init__(self, name: str, version: str | None = None) -> None:
        """Store the missing package name and optional version."""
        self.name: str = name
        self.version: str | None = version
        target = f"{name}=={version}" if version else name
        super().__init__(f"Package '{target}' not found on PyPI")


class NetworkError(Exception):
    """Raised when a network request fails."""

    def __init__(self, message: str) -> None:
        """Wrap a network failure message."""
        super().__init__(f"Network error: {message}")


def _pypi_url(name: str, version: str | None) -> str:
    if version:
        return f"{PYPI_BASE_URL}/{name}/{version}/json"
    return f"{PYPI_BASE_URL}/{name}/json"


def _fetch(name: str, version: str | None) -> PyPIResponse:
    """Fetch the raw PyPI JSON payload for a package.

    Returns:
        The decoded JSON body from the PyPI JSON API.

    Raises:
        PackageNotFoundError: If PyPI responds 404 for the package/version.
        NetworkError: If the request fails or returns a non-success status.
    """
    url = _pypi_url(name, version)
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # ruff: ignore[magic-value-comparison]
        raise PackageNotFoundError(name, version)

    try:
        _ = response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        msg = f"PyPI returned HTTP {exc.response.status_code}"
        raise NetworkError(msg) from exc

    return _decode_response(response)


def _decode_response(response: httpx.Response) -> PyPIResponse:
    try:
        body = cast("object", response.json())
    except ValueError as exc:
        msg = "PyPI returned invalid JSON"
        raise NetworkError(msg) from exc
    try:
        return _validate_response(body)
    except ResponseValidationError as exc:
        msg = f"malformed response from PyPI: {exc}"
        raise NetworkError(msg) from exc


def _validate_vulnerability(value: object, index: int) -> None:
    path = f"$.vulnerabilities[{index}]"
    vuln = expect_mapping(value, source="PyPI", path=path)
    _ = expect_string(vuln.get("id"), source="PyPI", path=f"{path}.id")
    _ = optional_string(vuln, "summary", source="PyPI", path=path)
    _ = optional_string_list(vuln, "aliases", source="PyPI", path=path)
    _ = optional_string_list(vuln, "fixed_in", source="PyPI", path=path)


def _validate_info(value: object) -> None:
    info = expect_mapping(value, source="PyPI", path="$.info")
    _ = expect_string(info.get("name"), source="PyPI", path="$.info.name")
    _ = expect_string(info.get("version"), source="PyPI", path="$.info.version")
    for key in (
        "summary",
        "author",
        "author_email",
        "maintainer",
        "license",
        "license_expression",
        "requires_python",
        "home_page",
        "keywords",
    ):
        _ = optional_string(info, key, source="PyPI", path="$.info")
    _ = optional_string_mapping(info, "project_urls", source="PyPI", path="$.info")
    _ = optional_string_list(info, "requires_dist", source="PyPI", path="$.info")
    _ = optional_string_list(info, "classifiers", source="PyPI", path="$.info")


def _validate_response(body: object) -> PyPIResponse:
    root = expect_mapping(body, source="PyPI", path="$")
    _validate_info(root.get("info"))
    raw_vulnerabilities = root.get("vulnerabilities", [])
    vulnerabilities = expect_list(
        raw_vulnerabilities, source="PyPI", path="$.vulnerabilities"
    )
    for index, vulnerability in enumerate(vulnerabilities):
        _validate_vulnerability(vulnerability, index)
    return cast("PyPIResponse", cast("object", root))


def _parse_keywords(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def _parse_vulnerabilities(raw: list[PyPIVulnerability]) -> list[Vulnerability]:
    return [
        Vulnerability(
            id=v["id"],
            aliases=v.get("aliases") or [],
            summary=v.get("summary") or "",
            fixed_in=v.get("fixed_in") or [],
        )
        for v in raw
    ]


def _parse_license(
    info: PyPIInfo,
) -> tuple[str | None, Literal["expression", "legacy"] | None]:
    expression = info.get("license_expression")
    if expression:
        return expression, "expression"
    legacy = info.get("license")
    return legacy, "legacy" if legacy else None


def get_package(name: str, version: str | None = None) -> PackageInfo:
    """Get metadata for a package from PyPI.

    Args:
        name: Package name to look up.
        version: Optional specific version; if ``None`` the latest is fetched.

    Returns:
        A :class:`PackageInfo` with ``source="remote"``. Not-found and network
        failures propagate from :func:`_fetch`.
    """
    data = _fetch(name, version)
    info: PyPIInfo = data["info"]
    license_value, license_source = _parse_license(info)
    return PackageInfo(
        name=info["name"],
        version=info["version"],
        summary=info.get("summary"),
        author=info.get("author"),
        author_email=info.get("author_email"),
        maintainer=info.get("maintainer"),
        license=license_value,
        license_source=license_source,
        python_requires=info.get("requires_python"),
        homepage=info.get("home_page"),
        project_urls=info.get("project_urls") or {},
        dependencies=info.get("requires_dist") or [],
        classifiers=info.get("classifiers") or [],
        keywords=_parse_keywords(info.get("keywords")),
        files=None,
        vulnerabilities=_parse_vulnerabilities(data.get("vulnerabilities", [])),
        source="remote",
        retrieved_at=utc_now(),
    )
