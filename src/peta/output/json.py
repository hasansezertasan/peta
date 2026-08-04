"""JSON output formatters."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = [
    "format_compare",
    "format_deps",
    "format_files",
    "format_info",
    "format_versions",
]


def _package_dict(pkg: PackageInfo) -> dict[str, object]:
    return {
        "name": pkg.name,
        "version": pkg.version,
        "summary": pkg.summary,
        "author": pkg.author,
        "license": pkg.license,
        "python_requires": pkg.python_requires,
        "homepage": pkg.homepage,
        "project_urls": pkg.project_urls,
        "dependencies": pkg.dependencies,
        "vulnerabilities": [
            {
                "id": v.id,
                "aliases": v.aliases,
                "summary": v.summary,
                "fixed_in": v.fixed_in,
                "severity": v.severity,
            }
            for v in pkg.vulnerabilities
        ],
        "download_count": pkg.download_count,
        "dependent_count": pkg.dependent_count,
        "source": pkg.source,
    }


def format_info(pkg: PackageInfo) -> str:
    """Format :class:`PackageInfo` as a JSON string.

    Returns:
        The metadata serialized as an indented JSON string.
    """
    return json.dumps(_package_dict(pkg), indent=2)


def format_compare(a: PackageInfo, b: PackageInfo) -> str:
    """Format two :class:`PackageInfo` objects as a JSON comparison string.

    Returns:
        A ``{"packages": [a, b]}`` JSON string, each package in the same
        format as :func:`format_info`.
    """
    return json.dumps({"packages": [_package_dict(a), _package_dict(b)]}, indent=2)


def format_deps(pkg: PackageInfo) -> str:
    """Format a package's dependency list as a JSON string.

    Returns:
        The dependency list serialized as an indented JSON string.
    """
    data = {
        "name": pkg.name,
        "version": pkg.version,
        "dependencies": [{"name": d} for d in pkg.dependencies],
    }
    return json.dumps(data, indent=2)


def format_files(pkg: PackageInfo) -> str:
    """Format a package's file list as a JSON string.

    Returns:
        The file list serialized as an indented JSON string.
    """
    data = {"name": pkg.name, "version": pkg.version, "files": pkg.files or []}
    return json.dumps(data, indent=2)


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format a version list as a JSON string.

    Returns:
        The version list serialized as an indented JSON string.
    """
    return json.dumps({"name": name, "versions": versions}, indent=2)
