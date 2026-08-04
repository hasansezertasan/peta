"""Shared best-effort OSV + stats enrichment for ``info`` and ``compare``."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from peta.core import osv, stats
from peta.core.vulns import merge_vulnerabilities

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["enrich"]


def _enrich_with_osv(pkg: PackageInfo) -> PackageInfo:
    osv_vulns = osv.get_vulnerabilities(pkg.name, pkg.version)
    return dataclasses.replace(
        pkg, vulnerabilities=merge_vulnerabilities(pkg.vulnerabilities, osv_vulns)
    )


def _enrich_with_stats(pkg: PackageInfo) -> PackageInfo:
    return dataclasses.replace(
        pkg,
        download_count=stats.get_download_count(pkg.name),
        dependent_count=stats.get_dependent_count(
            pkg.name, api_key=stats.libraries_io_api_key()
        ),
    )


def enrich(pkg: PackageInfo, *, no_osv: bool, no_stats: bool) -> PackageInfo:
    """Best-effort enrich a package with OSV vulnerabilities and usage stats.

    Never raises: both lookups are best-effort and never affect exit codes.

    Returns:
        The enriched package metadata.
    """
    if not no_osv:
        pkg = _enrich_with_osv(pkg)
    if not no_stats:
        pkg = _enrich_with_stats(pkg)
    return pkg
