"""JSON output formatters."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "format_compare",
    "format_dep_tree",
    "format_files",
    "format_info",
    "format_versions",
    "format_why",
]


def _package_dict(pkg: PackageInfo) -> dict[str, object]:
    return {
        "name": pkg.name,
        "version": pkg.version,
        "summary": pkg.summary,
        "author": pkg.author,
        "author_email": pkg.author_email,
        "maintainer": pkg.maintainer,
        "license": pkg.license,
        "license_source": pkg.license_source,
        "python_requires": pkg.python_requires,
        "homepage": pkg.homepage,
        "project_urls": pkg.project_urls,
        "classifiers": pkg.classifiers,
        "keywords": pkg.keywords,
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


def _node_dict(node: DependencyNode) -> dict[str, object]:
    return {
        "name": node.name,
        "version_spec": node.version_spec,
        "installed_version": node.installed_version,
        "circular": node.circular,
        "children": [_node_dict(child) for child in node.children],
    }


def format_dep_tree(node: DependencyNode) -> str:
    """Format a recursive dependency tree as a JSON string.

    Returns:
        The dependency tree serialized as an indented JSON string.
    """
    return json.dumps(_node_dict(node), indent=2)


def format_why(target: str, paths: list[list[str]]) -> str:
    """Format root-to-target dependency chains as a JSON string.

    Returns:
        A ``{"target": ..., "paths": [[...], ...]}`` JSON string.
    """
    return json.dumps({"target": target, "paths": paths}, indent=2)


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
