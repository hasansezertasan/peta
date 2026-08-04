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


def merge_vulnerabilities(
    existing: list[Vulnerability], extra: list[Vulnerability]
) -> list[Vulnerability]:
    """Merge two vulnerability lists, deduping by identity.

    Two vulnerabilities are the same if they share their ``id`` or any
    overlapping alias. When duplicates are found, one entry is kept: the
    result prefers a non-``None`` ``severity`` and unions ``aliases`` and
    ``fixed_in``.

    Args:
        existing: Vulnerabilities already known (e.g. from PyPI).
        extra: Additional vulnerabilities to merge in (e.g. from OSV).

    Returns:
        A deduped list, with ``existing`` entries first, in order.
    """
    merged: list[Vulnerability] = list(existing)
    for candidate in extra:
        cand_ids = _identity(candidate)
        match_index = next(
            (i for i, v in enumerate(merged) if _identity(v) & cand_ids), None
        )
        if match_index is None:
            merged.append(candidate)
        else:
            merged[match_index] = _combine(merged[match_index], candidate)
    return merged
