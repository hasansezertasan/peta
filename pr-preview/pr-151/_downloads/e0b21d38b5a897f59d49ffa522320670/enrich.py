"""Best-effort enrichment orchestration over :mod:`peta.core.providers`.

Providers are consulted independently and merged deterministically, so one
source failing can never discard another's evidence, and two sources answering
the same field disagree loudly rather than silently overwriting each other.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from peta.core.models import EnrichmentFailure, ProviderConflict
from peta.core.output import SourceRecord
from peta.core.providers import (
    DEFAULT_PROVIDERS,
    CountEvidence,
    ProviderResult,
    VulnerabilityEvidence,
)
from peta.core.vulns import merge_vulnerabilities

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from peta.core.models import PackageInfo
    from peta.core.providers import Capability, EnrichmentProvider, ProviderGroup

__all__ = ["enrich"]


def _disabled_groups(*, no_osv: bool, no_stats: bool) -> frozenset[ProviderGroup]:
    groups: set[ProviderGroup] = set()
    if no_osv:
        groups.add("vulnerabilities")
    if no_stats:
        groups.add("stats")
    return frozenset(groups)


def _collect(
    pkg: PackageInfo,
    providers: Iterable[EnrichmentProvider],
    disabled: frozenset[ProviderGroup],
) -> list[ProviderResult]:
    """Ask every provider for its evidence, skipping disabled groups.

    Returns:
        One result per provider, in the order they were consulted.
    """
    return [
        ProviderResult(
            provider=provider.name,
            capability=provider.capability,
            state="skipped",
            subject=pkg.name,
        )
        if provider.group in disabled
        else provider.fetch(pkg)
        for provider in providers
    ]


def _with_count(pkg: PackageInfo, capability: Capability, count: int) -> PackageInfo:
    """Write a scalar count onto the field its capability names.

    Returns:
        The package carrying the count.
    """
    if capability == "download_count":
        return dataclasses.replace(pkg, download_count=count)
    return dataclasses.replace(pkg, dependent_count=count)


def _merge_count(
    pkg: PackageInfo,
    result: ProviderResult,
    count: int,
    claims: dict[str, tuple[str, int]],
) -> tuple[PackageInfo, ProviderConflict | None]:
    """Apply a count unless another provider already claimed the field.

    The first claimant wins, so the outcome depends on provider order rather
    than on which lookup happened to finish last.

    Returns:
        The updated package, and a conflict when a later provider disagreed.
    """
    prior = claims.get(result.field)
    if prior is None:
        claims[result.field] = (result.provider, count)
        return _with_count(pkg, result.capability, count), None
    holder, held = prior
    if held == count:
        return pkg, None
    conflict = ProviderConflict(
        field=result.field, kept=holder, discarded=result.provider
    )
    return pkg, conflict


def _merge(pkg: PackageInfo, results: Sequence[ProviderResult]) -> PackageInfo:
    """Fold provider evidence into the package in consultation order.

    Vulnerabilities union across sources and cannot conflict; scalar counts are
    first-writer-wins, and a later provider offering a different value is
    recorded as a conflict instead of overwriting.

    Returns:
        The package carrying every provider's evidence.
    """
    conflicts: list[ProviderConflict] = []
    claims: dict[str, tuple[str, int]] = {}
    for result in results:
        evidence = result.evidence
        if isinstance(evidence, VulnerabilityEvidence):
            pkg = dataclasses.replace(
                pkg,
                vulnerabilities=merge_vulnerabilities(
                    pkg.vulnerabilities, evidence.vulnerabilities
                ),
            )
        elif isinstance(evidence, CountEvidence):
            pkg, conflict = _merge_count(pkg, result, evidence.count, claims)
            if conflict is not None:
                conflicts.append(conflict)
    return dataclasses.replace(pkg, enrichment_conflicts=conflicts)


def _provenance(pkg: PackageInfo, results: Sequence[ProviderResult]) -> PackageInfo:
    """Record a source per provider, and a failure per failed provider.

    Returns:
        The package carrying provenance for every consulted provider.
    """
    sources = [
        SourceRecord(
            name=result.provider,
            state=result.state,
            target=result.subject,
            retrieved_at=result.retrieved_at,
            reason=result.reason,
            fields=[result.field],
        )
        for result in results
    ]
    failures = [
        EnrichmentFailure(source=result.provider, reason=result.reason or "")
        for result in results
        if result.state == "failed"
    ]
    return dataclasses.replace(
        pkg,
        enrichment_sources=[*pkg.enrichment_sources, *sources],
        enrichment_failures=[*pkg.enrichment_failures, *failures],
    )


def enrich(
    pkg: PackageInfo,
    *,
    no_osv: bool,
    no_stats: bool,
    providers: Sequence[EnrichmentProvider] | None = None,
) -> PackageInfo:
    """Best-effort enrich a package from every configured provider.

    Never raises: providers report failure as a result state, so an enrichment
    problem stays visible in the output without affecting exit codes.

    Args:
        pkg: The resolved package to enrich.
        no_osv: Skip the vulnerability provider group.
        no_stats: Skip the usage-statistics provider group.
        providers: The providers to consult, in conflict-priority order.
            Injectable so callers and tests can substitute sources; defaults to
            :data:`~peta.core.providers.DEFAULT_PROVIDERS`. Resolved at call
            time rather than bound as a default argument, so the registry stays
            swappable.

    Returns:
        The enriched package metadata.
    """
    disabled = _disabled_groups(no_osv=no_osv, no_stats=no_stats)
    results = _collect(
        pkg, DEFAULT_PROVIDERS if providers is None else providers, disabled
    )
    return _provenance(_merge(pkg, results), results)
