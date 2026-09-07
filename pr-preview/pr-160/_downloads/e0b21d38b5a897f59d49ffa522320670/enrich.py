"""Best-effort enrichment orchestration over :mod:`peta.core.providers`.

Providers are consulted independently and merged deterministically, so one
source failing can never discard another's evidence, and two sources answering
the same field disagree loudly rather than silently overwriting each other.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from peta.core.models import EnrichmentFailure, ProviderConflict, ProviderWarning
from peta.core.output import SourceRecord, utc_now
from peta.core.providers import (
    CAPABILITY_GROUPS,
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

_UNKNOWN_PROVIDER = "unidentified provider"
"""Stand-in name for a provider whose own identity could not be read."""

_UNKNOWN_CAPABILITY = cast("Capability", cast("object", "unknown"))
"""Stand-in capability, deliberately absent from every capability map.

Not one of the declared literals, so a result carrying it has no attributable
field. Cast through ``object`` because that mismatch is the whole point.
"""

_UNATTRIBUTED = "an earlier pass"
"""Named owner for a count already present without a source record."""

_COMPLETED_STATES = frozenset({"success", "empty"})
"""States describing a lookup that ran, so must report when it returned."""


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
    return [_consult(provider, pkg, disabled) for provider in providers]


def _consult(
    provider: EnrichmentProvider, pkg: PackageInfo, disabled: frozenset[ProviderGroup]
) -> ProviderResult:
    """Resolve one provider's outcome, containing every way it can misbehave.

    Everything the provider controls is read inside the guarded path: its own
    identity and capability (either can be a property that raises), the group
    lookup for that capability, and the fetch itself. The recovery path uses
    only locals, so it can never re-trip the fault it is reporting.

    Returns:
        The provider's result, or a failed result describing what went wrong.
    """
    name = _UNKNOWN_PROVIDER
    capability = _UNKNOWN_CAPABILITY
    try:
        name = provider.name
        if not isinstance(cast("object", name), str):
            reason = f"provider name is {type(name).__name__}, not str"
            return _rejected(name, capability, pkg, reason)
        capability = provider.capability
        return _dispatch(name, capability, provider, pkg, disabled)
    # A misbehaving provider is contained here, never propagated to the caller.
    except Exception as exc:  # ruff: ignore[blind-except]
        reason = f"provider raised {type(exc).__name__}: {exc}"
        return _rejected(name, capability, pkg, reason)


def _dispatch(
    name: str,
    capability: Capability,
    provider: EnrichmentProvider,
    pkg: PackageInfo,
    disabled: frozenset[ProviderGroup],
) -> ProviderResult:
    """Consult a provider whose identity has already been read safely.

    Returns:
        A skipped result for a disabled group, a failed result for a capability
        peta does not know, or the provider's own answer.
    """
    group = CAPABILITY_GROUPS.get(capability)
    if group is None:
        # Checked directly rather than caught: no opt-out flag can gate a
        # capability peta does not know, so consulting it would run it ungated,
        # and inferring this from a ``KeyError`` would also misreport a
        # provider's own internal lookup failures.
        reason = f"provider declares unknown capability {capability!r}"
        return _rejected(name, capability, pkg, reason)
    if group in disabled:
        return ProviderResult(
            provider=name, capability=capability, state="skipped", subject=pkg.name
        )
    return _accepted(name, capability, pkg, provider.fetch(pkg))


def _safe_capability(capability: Capability) -> Capability:
    """Normalize a capability to one safe to store on a result.

    A provider can return anything at runtime despite the annotation,
    including something unhashable such as a list. ``capability in
    CAPABILITY_GROUPS`` itself raises ``TypeError`` for such a value, and an
    unhashable or unknown capability stored on a result would blow up later
    when :attr:`ProviderResult.field` looks it up outside any guard.

    Returns:
        The given capability if it is a hashable, known one; otherwise
        :data:`_UNKNOWN_CAPABILITY`.
    """
    try:
        known = capability in CAPABILITY_GROUPS
    except TypeError:
        return _UNKNOWN_CAPABILITY
    return capability if known else _UNKNOWN_CAPABILITY


def _rejected(
    name: str, capability: Capability, pkg: PackageInfo, reason: str
) -> ProviderResult:
    """Describe a provider that misbehaved, in that provider's own terms.

    Both ``name`` and ``capability`` are normalized: ``reason`` already
    carries the offending values via ``!r`` where relevant, and an
    unhashable name or capability stored on the result would crash the
    set comprehension in :func:`_resolved_this_pass`.

    Returns:
        A failed result attributed to the consulted provider.
    """
    safe_name = name if isinstance(cast("object", name), str) else _UNKNOWN_PROVIDER
    return ProviderResult(
        provider=safe_name,
        capability=_safe_capability(capability),
        state="failed",
        subject=pkg.name,
        retrieved_at=utc_now(),
        reason=reason,
    )


def _mismatch(name: str, capability: Capability, result: ProviderResult) -> str | None:
    """Report how a result disagrees with the provider that returned it.

    ``ProviderResult`` validates that its own parts agree, but nothing ties a
    self-consistent result back to the provider actually consulted. Without
    this a provider in the vulnerability group could return a
    ``download_count`` result and populate statistics under ``--no-stats``.

    ``subject`` is deliberately not checked: a provider may legitimately answer
    about a normalized form of the requested name.

    Returns:
        A description of the disagreement, or ``None`` when they agree.
    """
    if result.provider != name:
        return f"provider returned a result attributed to {result.provider!r}"
    if result.capability != capability:
        return (
            f"provider declares capability {capability!r} but returned "
            f"{result.capability!r}"
        )
    return None


def _accepted(
    name: str, capability: Capability, pkg: PackageInfo, result: ProviderResult
) -> ProviderResult:
    """Accept a result once it agrees with the provider that returned it.

    Returns:
        The result, stamped if it completed without a retrieval time, or a
        failed result when it does not belong to this provider.
    """
    mismatch = _mismatch(name, capability, result)
    if mismatch is not None:
        return _rejected(name, capability, pkg, mismatch)
    if result.state in _COMPLETED_STATES and result.retrieved_at is None:
        # The contract promises a retrieval time for every completed lookup, so
        # stamp it here rather than discarding otherwise-good evidence.
        return dataclasses.replace(result, retrieved_at=utc_now())
    return result


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
    field: str,
    count: int,
    claims: dict[str, tuple[str, int]],
) -> tuple[PackageInfo, ProviderConflict | None]:
    """Apply a count unless another provider already claimed the field.

    The first claimant wins, so the outcome depends on provider order rather
    than on which lookup happened to finish last.

    Returns:
        The updated package, and a conflict when a later provider disagreed.
    """
    prior = claims.get(field)
    holder = None if prior is None else prior[0]
    if prior is None or holder == result.provider:
        # A new claim, or the owner refreshing its own: a count such as monthly
        # downloads legitimately changes between lookups, and a source can
        # never disagree with itself.
        claims[field] = (result.provider, count)
        return _with_count(pkg, result.capability, count), None
    if prior[1] == count:
        return pkg, None
    conflict = ProviderConflict(field=field, kept=prior[0], discarded=result.provider)
    return pkg, conflict


def _existing_claims(pkg: PackageInfo) -> dict[str, tuple[str, int]]:
    """Recover the scalar claims an earlier enrichment pass already made.

    ``enrich`` can be composed in stages. Without this, a second pass starts
    with no claims, so its first provider silently overwrites a value the first
    pass established while provenance keeps both sources.

    Returns:
        The claimed field paths mapped to their owning source and value.
    """
    # Reversed so the *first* successful source for a field wins the dict
    # comprehension: the value in the package came from whichever source
    # claimed it first, not from the last one that reported the same field.
    owners = {
        record.fields[0]: record.name
        for record in reversed(pkg.enrichment_sources)
        if record.state == "success" and record.fields
    }
    counts = {
        "result.download_count": pkg.download_count,
        "result.dependent_count": pkg.dependent_count,
    }
    return {
        field: (owners.get(field, _UNATTRIBUTED), value)
        for field, value in counts.items()
        if value is not None
    }


def _merge(pkg: PackageInfo, results: Sequence[ProviderResult]) -> PackageInfo:
    """Fold provider evidence into the package in consultation order.

    Vulnerabilities union across sources and cannot conflict; scalar counts are
    first-writer-wins, and a later provider offering a different value is
    recorded as a conflict instead of overwriting.

    Returns:
        The package carrying every provider's evidence.
    """
    conflicts: list[ProviderConflict] = []
    reconciled: set[tuple[str, str]] = set()
    claims = _existing_claims(pkg)
    for result in results:
        evidence = result.evidence
        if isinstance(evidence, VulnerabilityEvidence):
            pkg = dataclasses.replace(
                pkg,
                vulnerabilities=merge_vulnerabilities(
                    pkg.vulnerabilities, evidence.vulnerabilities
                ),
            )
        elif isinstance(evidence, CountEvidence) and result.field is not None:
            pkg, conflict = _merge_count(
                pkg, result, result.field, evidence.count, claims
            )
            if conflict is not None:
                conflicts.append(conflict)
            else:
                reconciled.add((result.field, result.provider))
    prior = [
        c for c in pkg.enrichment_conflicts if (c.field, c.discarded) not in reconciled
    ]
    return dataclasses.replace(pkg, enrichment_conflicts=[*prior, *conflicts])


def _resolved_this_pass(
    results: Sequence[ProviderResult],
) -> set[tuple[str, str | None]]:
    """Name the ``(source, field)`` pairs a completed lookup now answers.

    ``empty`` counts as resolved alongside ``success``: a source that was
    queried and confirmed it holds nothing has answered the question just as
    definitively, so an earlier failure for it is equally stale. ``skipped``
    and ``unavailable`` do not, since no lookup happened.

    Returns:
        One pair per completed result, so a stale failure for the same source
        and field can be told apart from an unrelated one.
    """
    return {
        (result.provider, result.field)
        for result in results
        if result.state in _COMPLETED_STATES
    }


def _provenance(pkg: PackageInfo, results: Sequence[ProviderResult]) -> PackageInfo:
    """Record a source per provider, and a failure per failed provider.

    A failure recorded in an earlier pass is dropped once this pass reports a
    success for the same source and field, so a provider that fails once and
    then recovers does not leave a permanently stale failure behind. Matching
    on both source and field means a provider succeeding at one field never
    clears an unrelated, still-failing one.

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
            freshness=result.freshness,
            # An unattributable result claims no field rather than an
            # invented one.
            fields=[] if result.field is None else [result.field],
        )
        for result in results
    ]
    failures = [
        EnrichmentFailure(
            source=result.provider, reason=result.reason or "", field=result.field
        )
        for result in results
        if result.state == "failed"
    ]
    resolved = _resolved_this_pass(results)
    prior_failures = [
        failure
        for failure in pkg.enrichment_failures
        if (failure.source, failure.field) not in resolved
    ]
    new_warnings: list[ProviderWarning] = [
        warning for result in results for warning in result.warnings
    ]
    return dataclasses.replace(
        pkg,
        enrichment_sources=[*pkg.enrichment_sources, *sources],
        enrichment_failures=[*prior_failures, *failures],
        provider_warnings=[*pkg.provider_warnings, *new_warnings],
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
