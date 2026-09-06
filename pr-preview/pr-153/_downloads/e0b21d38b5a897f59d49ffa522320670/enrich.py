"""Shared best-effort OSV + stats enrichment for ``info`` and ``compare``."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from peta.core import osv, stats
from peta.core.models import EnrichmentFailure
from peta.core.output import SourceRecord, SourceState, utc_now
from peta.core.validation import EnrichmentError
from peta.core.vulns import merge_vulnerabilities

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["enrich"]


def _enrich_with_osv(pkg: PackageInfo) -> PackageInfo:
    try:
        osv_vulns = osv.get_vulnerabilities(pkg.name, pkg.version)
    except EnrichmentError as exc:
        return _with_failure(pkg, exc)
    pkg = dataclasses.replace(
        pkg, vulnerabilities=merge_vulnerabilities(pkg.vulnerabilities, osv_vulns)
    )
    state: SourceState = "success" if osv_vulns else "empty"
    return _with_source(pkg, "osv", state, fields=["result.vulnerabilities"])


def _with_source(
    pkg: PackageInfo,
    source: str,
    state: SourceState,
    *,
    fields: list[str],
    reason: str | None = None,
) -> PackageInfo:
    record = SourceRecord(
        name=source,
        state=state,
        target=pkg.name,
        retrieved_at=utc_now() if state in {"success", "empty", "failed"} else None,
        reason=reason,
        fields=fields,
    )
    return dataclasses.replace(
        pkg, enrichment_sources=[*pkg.enrichment_sources, record]
    )


def _with_failure(pkg: PackageInfo, exc: EnrichmentError) -> PackageInfo:
    failure = EnrichmentFailure(source=exc.source, reason=exc.reason)
    pkg = dataclasses.replace(
        pkg, enrichment_failures=[*pkg.enrichment_failures, failure]
    )
    fields = {
        "osv": ["result.vulnerabilities"],
        "pypistats": ["result.download_count"],
        "libraries.io": ["result.dependent_count"],
    }.get(exc.source, [])
    return _with_source(pkg, exc.source, "failed", fields=fields, reason=exc.reason)


def _enrich_with_stats(pkg: PackageInfo) -> PackageInfo:
    try:
        download_count = stats.get_download_count(pkg.name)
    except EnrichmentError as exc:
        pkg = _with_failure(pkg, exc)
    else:
        pkg = dataclasses.replace(pkg, download_count=download_count)
        state: SourceState = "success" if download_count is not None else "empty"
        pkg = _with_source(pkg, "pypistats", state, fields=["result.download_count"])
    api_key = stats.libraries_io_api_key()
    if api_key is None:
        return _with_source(
            pkg,
            "libraries.io",
            "unavailable",
            fields=["result.dependent_count"],
            reason="LIBRARIES_IO_API_KEY is not configured",
        )
    try:
        dependent_count = stats.get_dependent_count(pkg.name, api_key=api_key)
    except EnrichmentError as exc:
        return _with_failure(pkg, exc)
    pkg = dataclasses.replace(pkg, dependent_count=dependent_count)
    state = "success" if dependent_count is not None else "empty"
    return _with_source(pkg, "libraries.io", state, fields=["result.dependent_count"])


def enrich(pkg: PackageInfo, *, no_osv: bool, no_stats: bool) -> PackageInfo:
    """Best-effort enrich a package with OSV vulnerabilities and usage stats.

    Never raises: both lookups are best-effort and never affect exit codes.

    Returns:
        The enriched package metadata.
    """
    if no_osv:
        pkg = _with_source(pkg, "osv", "skipped", fields=["result.vulnerabilities"])
    else:
        pkg = _enrich_with_osv(pkg)
    if no_stats:
        pkg = _with_source(
            pkg, "pypistats", "skipped", fields=["result.download_count"]
        )
        pkg = _with_source(
            pkg, "libraries.io", "skipped", fields=["result.dependent_count"]
        )
    else:
        pkg = _enrich_with_stats(pkg)
    return pkg
