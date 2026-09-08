"""Dedup/merge of vulnerabilities from multiple sources."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from peta.core.models import Vulnerability

__all__ = ["merge_vulnerabilities"]


def _identity(vuln: Vulnerability) -> set[str]:
    return {vuln.id, *vuln.aliases}


def _combine(existing: Vulnerability, extra: Vulnerability) -> Vulnerability:
    severity = existing.severity or extra.severity
    # Fold the absorbed entry's own id in as an alias (unless it equals the
    # surviving id) so the merged entry's identity set stays closed — otherwise
    # a later item sharing only that id would fail to dedup.
    candidates = [*existing.aliases, *extra.aliases, extra.id]
    aliases = [a for a in dict.fromkeys(candidates) if a != existing.id]
    fixed_in = list(dict.fromkeys([*existing.fixed_in, *extra.fixed_in]))
    return replace(existing, aliases=aliases, fixed_in=fixed_in, severity=severity)


def _matching_indices(merged: list[Vulnerability], cand_ids: set[str]) -> list[int]:
    return [i for i, v in enumerate(merged) if _identity(v) & cand_ids]


def _fold_in(
    merged: list[Vulnerability], candidate: Vulnerability, indices: list[int]
) -> Vulnerability:
    combined = merged[indices[0]]
    for i in indices[1:]:
        combined = _combine(combined, merged[i])
    return _combine(combined, candidate)


def merge_vulnerabilities(
    existing: list[Vulnerability], extra: list[Vulnerability]
) -> list[Vulnerability]:
    """Merge two vulnerability lists, deduping by identity.

    Two vulnerabilities are the same if they share their ``id`` or any
    overlapping alias. When a candidate's identity bridges several existing
    entries (e.g. it carries aliases of two otherwise-unrelated entries),
    ALL of them are folded into one cumulative entry rather than merging
    into only the first match. The result prefers a non-``None``
    ``severity`` and unions ``aliases`` and ``fixed_in``.

    Args:
        existing: Vulnerabilities already known (e.g. from PyPI).
        extra: Additional vulnerabilities to merge in (e.g. from OSV).

    Returns:
        A deduped list, with ``existing`` entries first, in order.
    """
    merged: list[Vulnerability] = list(existing)
    for candidate in extra:
        indices = _matching_indices(merged, _identity(candidate))
        if not indices:
            merged.append(candidate)
            continue
        combined = _fold_in(merged, candidate, indices)
        redundant = set(indices[1:])
        merged = [
            combined if i == indices[0] else v
            for i, v in enumerate(merged)
            if i not in redundant
        ]
    return merged
