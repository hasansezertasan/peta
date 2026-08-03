"""JSON output formatters."""

from __future__ import annotations

import json

from peta.core.models import PackageInfo


def format_info(pkg: PackageInfo) -> str:
    """Format :class:`PackageInfo` as a JSON string."""
    data = {
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
            {"id": v.id, "aliases": v.aliases, "summary": v.summary, "fixed_in": v.fixed_in}
            for v in pkg.vulnerabilities
        ],
        "source": pkg.source,
    }
    return json.dumps(data, indent=2)


def format_deps(pkg: PackageInfo) -> str:
    """Format a package's dependency list as a JSON string."""
    data = {
        "name": pkg.name,
        "version": pkg.version,
        "dependencies": [{"name": d} for d in pkg.dependencies],
    }
    return json.dumps(data, indent=2)


def format_files(pkg: PackageInfo) -> str:
    """Format a package's file list as a JSON string."""
    data = {"name": pkg.name, "version": pkg.version, "files": pkg.files or []}
    return json.dumps(data, indent=2)


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format a version list as a JSON string."""
    return json.dumps({"name": name, "versions": versions}, indent=2)
