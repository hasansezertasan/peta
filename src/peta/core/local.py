"""Local package metadata fetcher using importlib.metadata."""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from typing import cast

from peta.core.models import PackageInfo

__all__ = ["PackageNotFoundError", "get_package"]


class PackageNotFoundError(Exception):
    """Raised when a package is not installed locally."""

    def __init__(self, name: str) -> None:
        """Store the missing package name."""
        self.name: str = name
        super().__init__(f"Package '{name}' is not installed")


def _parse_project_urls(meta: importlib_metadata.PackageMetadata) -> dict[str, str]:
    urls: dict[str, str] = {}
    # importlib.metadata's PackageMetadata is untyped (email.Message based), so
    # get_all yields Any; cast the headers we read into the typed world.
    entries = cast("list[str]", meta.get_all("Project-URL") or [])
    for entry in entries:
        if ", " in entry:
            label, url = entry.split(", ", 1)
            urls[label.strip()] = url.strip()
    return urls


def _parse_keywords(meta: importlib_metadata.PackageMetadata) -> list[str]:
    raw = meta.get("Keywords")
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def get_package(name: str) -> PackageInfo:
    """Get metadata for a locally installed package.

    Args:
        name: Package name to look up.

    Returns:
        A :class:`PackageInfo` with ``source="local"``.

    Raises:
        PackageNotFoundError: If the package is not installed.
    """
    try:
        dist = importlib_metadata.distribution(name)
    except importlib_metadata.PackageNotFoundError as exc:
        raise PackageNotFoundError(name) from exc

    meta = dist.metadata
    files = [str(f) for f in dist.files] if dist.files else None
    return PackageInfo(
        name=meta["Name"],
        version=meta["Version"],
        summary=meta.get("Summary"),
        author=meta.get("Author"),
        author_email=meta.get("Author-email"),
        maintainer=meta.get("Maintainer"),
        license=meta.get("License"),
        python_requires=meta.get("Requires-Python"),
        homepage=meta.get("Home-page"),
        project_urls=_parse_project_urls(meta),
        dependencies=list(dist.requires) if dist.requires else [],
        classifiers=meta.get_all("Classifier") or [],
        keywords=_parse_keywords(meta),
        files=files,
        vulnerabilities=[],
        source="local",
    )
