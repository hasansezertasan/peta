"""The shared change vocabulary for every comparison peta makes.

``compare`` is the first of several commands that put two sides next to each
other — installed against registry, wheel against sdist, a recorded snapshot
against now, one release across two indexes, release against release over
time. They stay separate commands, because each takes different inputs and
flags, but they must describe what differs in the same terms, or the same
difference would be reported differently depending on how it was found.

This module is those terms and nothing else: groups, stable change kinds,
``before``/``after`` values, the "expected difference" flag, and the
"could not compare" record. It knows nothing about how any command gathers
its two sides; :mod:`peta.core.diff` is the package-and-release engine built
on it, and a new comparison should add its kinds here rather than invent a
parallel model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeAliasType

__all__ = [
    "CHANGE_GROUPS",
    "Change",
    "ChangeGroup",
    "ChangeKind",
    "ChangeSet",
    "Unknown",
    "Value",
]

# CodeQL does not yet recognize PEP 695 ``type`` statements as definitions when
# checking ``__all__``. Keep these runtime-visible assignments until it does.
ChangeGroup = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "ChangeGroup",
    Literal[
        "release",
        "python",
        "dependencies",
        "extras",
        "license",
        "vulnerabilities",
        "artifacts",
        "provenance",
    ],
)
ChangeKind = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "ChangeKind",
    Literal[
        "project_changed",
        "version_changed",
        "release_date_changed",
        "python_requires_changed",
        "dependency_added",
        "dependency_removed",
        "dependency_specifier_changed",
        "dependency_marker_changed",
        "dependency_extras_changed",
        "extra_added",
        "extra_removed",
        "license_changed",
        "vulnerability_added",
        "vulnerability_removed",
        "vulnerability_fixed_in_changed",
        "artifact_added",
        "artifact_removed",
        "artifact_hash_changed",
        "artifact_size_changed",
        "artifact_yanked_changed",
        "artifact_compatibility_changed",
        "provenance_changed",
    ],
)

CHANGE_GROUPS: tuple[ChangeGroup, ...] = (
    "release",
    "python",
    "dependencies",
    "extras",
    "license",
    "vulnerabilities",
    "artifacts",
    "provenance",
)
"""Every group, in the order renderers present them."""

Value = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "Value", str | int | bool | list[str] | dict[str, object] | None
)
"""A ``before``/``after`` value: always JSON-serializable as-is."""


@dataclass(frozen=True)
class Change:
    """One semantic difference between the two sides of a comparison."""

    group: ChangeGroup
    kind: ChangeKind
    subject: str
    """What changed: a dependency, advisory id, artifact slot, or field name."""
    before: Value
    after: Value
    expected: bool = False
    """Whether the difference follows from what was compared, not from drift.

    Two different releases necessarily ship different files, so their digests
    and sizes differ; the same file listed in two places should not. An
    expected difference is still recorded — it is true, and a consumer may
    want it — but renderers summarize rather than list it, so it cannot bury
    the differences that need attention.
    """


@dataclass(frozen=True)
class Unknown:
    """A group that could not be compared because a side has no evidence."""

    group: ChangeGroup
    reason: str


@dataclass(frozen=True)
class ChangeSet:
    """Every change between the two sides of a comparison, plus the unknowable."""

    changes: tuple[Change, ...]
    unknown: tuple[Unknown, ...] = ()

    def in_group(self, group: ChangeGroup) -> list[Change]:
        """Select the changes of one group, in their recorded order.

        Returns:
            The group's changes.
        """
        return [change for change in self.changes if change.group == group]
