"""PyPI JSON API client for remote package metadata."""

from __future__ import annotations

from typing import Any

import httpx

from peta.core.models import PackageInfo, Vulnerability

PYPI_BASE_URL = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10.0


class PackageNotFoundError(Exception):
    """Raised when a package is not found on PyPI."""

    def __init__(self, name: str, version: str | None = None) -> None:
        self.name = name
        self.version = version
        target = f"{name}=={version}" if version else name
        super().__init__(f"Package '{target}' not found on PyPI")


class NetworkError(Exception):
    """Raised when a network request fails."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Network error: {message}")


def _pypi_url(name: str, version: str | None) -> str:
    if version:
        return f"{PYPI_BASE_URL}/{name}/{version}/json"
    return f"{PYPI_BASE_URL}/{name}/json"


def _fetch(name: str, version: str | None) -> dict[str, Any]:
    url = _pypi_url(name, version)
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # noqa: PLR2004
        raise PackageNotFoundError(name, version)

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"PyPI returned HTTP {exc.response.status_code}") from exc

    data: dict[str, Any] = response.json()
    return data


def _parse_keywords(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def _parse_vulnerabilities(raw: list[dict[str, Any]]) -> list[Vulnerability]:
    return [
        Vulnerability(
            id=v["id"],
            aliases=v.get("aliases", []),
            summary=v.get("summary", ""),
            fixed_in=v.get("fixed_in", []),
        )
        for v in raw
    ]


def get_package(name: str, version: str | None = None) -> PackageInfo:
    """Get metadata for a package from PyPI.

    Args:
        name: Package name to look up.
        version: Optional specific version; if ``None`` the latest is fetched.

    Returns:
        A :class:`PackageInfo` with ``source="remote"``.

    Raises:
        PackageNotFoundError: If the package/version does not exist on PyPI.
        NetworkError: If the request fails.
    """
    data = _fetch(name, version)
    info: dict[str, Any] = data["info"]
    return PackageInfo(
        name=info["name"],
        version=info["version"],
        summary=info.get("summary"),
        author=info.get("author"),
        author_email=info.get("author_email"),
        maintainer=info.get("maintainer"),
        license=info.get("license"),
        python_requires=info.get("requires_python"),
        homepage=info.get("home_page"),
        project_urls=info.get("project_urls") or {},
        dependencies=info.get("requires_dist") or [],
        classifiers=info.get("classifiers", []),
        keywords=_parse_keywords(info.get("keywords")),
        files=None,
        vulnerabilities=_parse_vulnerabilities(data.get("vulnerabilities", [])),
        source="remote",
    )
