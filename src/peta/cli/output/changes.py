"""Shared wording for semantic change records.

Every human format presents a :class:`~peta.core.diff.ChangeSet` the same
way — one section per group, one line per change — and differs only in how it
escapes the pieces. The pieces are therefore built once here, as plain
untrusted strings, and each formatter makes them inert for its own format.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from peta.core.changes import CHANGE_GROUPS

if TYPE_CHECKING:
    from peta.core.changes import Change, ChangeGroup, ChangeKind, ChangeSet, Value

__all__ = ["GROUP_TITLES", "ChangeLine", "Section", "sections"]

GROUP_TITLES: dict[ChangeGroup, str] = {
    "release": "Release",
    "python": "Python",
    "dependencies": "Dependencies",
    "extras": "Extras",
    "license": "License",
    "vulnerabilities": "Vulnerabilities",
    "artifacts": "Artifacts",
    "provenance": "Provenance",
}

_LABELS: dict[ChangeKind, str] = {
    "dependency_url_changed": "url",
    "dependency_specifier_changed": "specifier",
    "dependency_marker_changed": "marker",
    "dependency_extras_changed": "extras",
    "vulnerability_fixed_in_changed": "fixed in",
    "artifact_hash_changed": "sha256",
    "artifact_size_changed": "size",
    "artifact_yanked_changed": "yanked",
    "artifact_compatibility_changed": "compatible",
    "provenance_changed": "provenance available",
}
"""The attribute a change is about, when the subject alone does not say."""


@dataclass(frozen=True)
class ChangeLine:
    """One change, split into the parts a formatter escapes separately."""

    symbol: str
    """``+`` added, ``-`` removed, ``~`` changed."""
    subject: str
    detail: str


@dataclass(frozen=True)
class Section:
    """One group's changes, or why the group could not be compared."""

    title: str
    lines: tuple[ChangeLine, ...] = ()
    unknown: str | None = None
    expected: int = 0
    """How many expected differences were summarized instead of listed."""

    @property
    def expected_note(self) -> str | None:
        """Summarize the expected differences that are not listed.

        Returns:
            One line naming how many there are, or ``None`` when there are none.
        """
        if not self.expected:
            return None
        noun = "difference" if self.expected == 1 else "differences"
        return (
            f"{self.expected} expected {noun} not listed "
            "(different files carry different digests and sizes)"
        )


def _value(value: Value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, dict):
        return _advisory(value)
    return _text(value)


def _text(value: str | list[str] | None) -> str:
    if isinstance(value, list):
        return ", ".join(value) or "none"
    return value or "none"


def _advisory(value: dict[str, object]) -> str:
    fixed = cast("list[str]", value.get("fixed_in") or [])
    fix = f"fixed in {', '.join(fixed) or 'no release'}"
    summary = value.get("summary")
    return f"{summary} ({fix})" if summary else fix


def _line(change: Change, arrow: str) -> ChangeLine:
    if change.kind.endswith("_added"):
        return ChangeLine("+", change.subject, _detail(change.subject, change.after))
    if change.kind.endswith("_removed"):
        return ChangeLine("-", change.subject, _detail(change.subject, change.before))
    label = _LABELS.get(change.kind)
    subject = f"{change.subject} {label}" if label else change.subject
    detail = f"{_value(change.before)} {arrow} {_value(change.after)}"
    return ChangeLine("~", subject, detail)


def _detail(subject: str, value: Value) -> str:
    """Describe an added or removed item, omitting a detail that repeats it.

    Returns:
        The item's value, or nothing when it is just the subject again.
    """
    text = _value(value)
    return "" if text == subject else text


def sections(diff: ChangeSet, *, arrow: str = "→") -> list[Section]:
    """Group a diff for display, in :data:`~peta.core.changes.CHANGE_GROUPS` order.

    Groups with no change are omitted, which is what makes the output
    changed-only; a group that could not be compared is kept, with its
    reason, so silence is never mistaken for "unchanged". Expected
    differences are counted rather than listed.

    Returns:
        One section per group that changed or could not be compared.
    """
    unknown = {entry.group: entry.reason for entry in diff.unknown}
    result: list[Section] = []
    for group in CHANGE_GROUPS:
        changes = diff.in_group(group)
        lines = tuple(_line(change, arrow) for change in changes if not change.expected)
        expected = sum(change.expected for change in changes)
        if changes or group in unknown:
            result.append(
                Section(GROUP_TITLES[group], lines, unknown.get(group), expected)
            )
    return result
