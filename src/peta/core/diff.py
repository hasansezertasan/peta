"""Semantic differences between two packages or two releases of one package.

:func:`diff_packages` explains what changed rather than restating both sides:
a dependency whose specifier moved is one ``dependency_specifier_changed``
record, not two differing counts. Records use the shared vocabulary in
:mod:`peta.core.changes`, so the same model serves the human renderers, the
JSON contract, and every other command that compares two sides.

Values are canonicalized before they are compared, so a formatting difference
never becomes a change: project and extra names follow PEP 503, specifier sets
compare as sets of canonical specifiers (``>=1.0`` equals ``>=1.0.0``), markers
compare in packaging's normalized form, and license expressions are
canonicalized as SPDX.

Absent evidence is not a change. When one side could not answer — its
advisory lookup failed, or its artifact listing was never retrieved — the
group is reported in :attr:`~peta.core.changes.ChangeSet.unknown` instead of
being diffed against an empty value that would read as "everything was
removed".
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from packaging.utils import canonicalize_name, canonicalize_version

from peta.core.changes import CHANGE_GROUPS, Change, ChangeSet, Unknown

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from peta.core.artifacts import ArtifactFile, ReleaseArtifacts
    from peta.core.cache import Provenance
    from peta.core.changes import ChangeGroup, ChangeKind, Value
    from peta.core.models import PackageInfo, Vulnerability

__all__ = ["ReleaseEvidence", "diff_packages"]


@dataclass(frozen=True)
class ReleaseEvidence:
    """The artifact listing retrieved for one side, or why there is none."""

    release: ReleaseArtifacts | None = None
    retrieval: Provenance | None = None
    reason: str | None = None
    """Why the listing is missing; ``None`` whenever :attr:`release` is set."""


def diff_packages(
    a: PackageInfo,
    b: PackageInfo,
    *,
    a_release: ReleaseEvidence | None = None,
    b_release: ReleaseEvidence | None = None,
    osv_skipped: bool = False,
) -> ChangeSet:
    """Explain every semantic change from ``a`` to ``b``.

    Args:
        a: The "before" side.
        b: The "after" side.
        a_release: ``a``'s artifact listing; ``None`` when artifacts were not
            requested, which leaves artifact groups out entirely.
        b_release: ``b``'s artifact listing, under the same rule.
        osv_skipped: Whether the OSV lookup was switched off, which leaves an
            installed package with no advisory evidence to compare.

    Returns:
        The changes, grouped in :data:`CHANGE_GROUPS` order.
    """
    changes = [
        *_release_changes(a, b),
        *_python_changes(a, b),
        *_dependency_changes(a.dependencies, b.dependencies),
        *_extra_changes(a.dependencies, b.dependencies),
        *_license_changes(a, b),
    ]
    unknown: list[Unknown] = []
    vulnerabilities = _vulnerability_changes(a, b, osv_skipped=osv_skipped)
    if isinstance(vulnerabilities, Unknown):
        unknown.append(vulnerabilities)
    else:
        changes.extend(vulnerabilities)
    if a_release is not None and b_release is not None:
        artifacts = _artifact_side_changes(a_release, b_release)
        if isinstance(artifacts, Unknown):
            unknown.extend(
                Unknown(group, artifacts.reason) for group in _ARTIFACT_GROUPS
            )
        else:
            changes.extend(artifacts)
    order = {group: index for index, group in enumerate(CHANGE_GROUPS)}
    changes.sort(key=lambda change: order[change.group])
    return ChangeSet(changes=tuple(changes), unknown=tuple(unknown))


# --- release and scalar fields ----------------------------------------------


def _release_changes(a: PackageInfo, b: PackageInfo) -> Iterator[Change]:
    if canonicalize_name(a.name) != canonicalize_name(b.name):
        yield Change("release", "project_changed", "project", a.name, b.name)
    if _version_key(a.version) != _version_key(b.version):
        yield Change("release", "version_changed", "version", a.version, b.version)


def _version_key(version: str) -> str:
    """Normalize a version so ``1.0`` and ``1.0.0`` are the same release.

    Returns:
        The canonical version, or the stripped text when it does not parse.
    """
    return canonicalize_version(version.strip(), strip_trailing_zero=True)


def _python_changes(a: PackageInfo, b: PackageInfo) -> Iterator[Change]:
    if _specifier_key(a.python_requires) != _specifier_key(b.python_requires):
        yield Change(
            "python",
            "python_requires_changed",
            "requires_python",
            a.python_requires,
            b.python_requires,
        )


def _specifier_key(value: str | None) -> frozenset[Specifier] | str | None:
    """Parse a specifier set so equivalent spellings compare equal.

    A frozenset of specifiers rather than the ``SpecifierSet`` itself:
    ``SpecifierSet.__eq__`` parses a ``str`` operand, so comparing a parsed
    side with an unparsable one would raise instead of reporting a change.

    Returns:
        The parsed specifiers, the stripped text when unparsable, or ``None``.
    """
    if value is None or not value.strip():
        return None
    try:
        return frozenset(SpecifierSet(value))
    except InvalidSpecifier:
        return value.strip()


def _license_changes(a: PackageInfo, b: PackageInfo) -> Iterator[Change]:
    if _license_key(a) != _license_key(b):
        yield Change("license", "license_changed", "license", a.license, b.license)


def _license_key(pkg: PackageInfo) -> str | None:
    """Canonicalize a license so ``mit OR apache-2.0`` equals its SPDX form.

    The declaration style is deliberately not part of the key: a project that
    moves ``BSD-3-Clause`` from the legacy ``License`` field to
    ``License-Expression`` declares the same license. Legacy text that is a
    valid SPDX expression is canonicalized too, for the same reason.

    Returns:
        The canonical expression, the stripped text, or ``None``.
    """
    value = pkg.license.strip() if pkg.license else None
    if not value:
        return None
    try:
        return str(canonicalize_license_expression(value))
    except InvalidLicenseExpression:
        return value


# --- dependencies ------------------------------------------------------------


_EXTRA_MARKER = re.compile(
    r"""extra\s*==\s*["']([^"']+)["']|["']([^"']+)["']\s*==\s*extra\b"""
)
"""An ``extra`` comparison, written either way round.

PEP 508 allows ``"dev" == extra`` as well as ``extra == "dev"``, and
packaging keeps the order it was given when it normalizes a marker.
"""


@dataclass(frozen=True)
class _Dependency:
    """One ``Requires-Dist`` entry in canonical, comparable form."""

    slot: str
    """Name plus gating extra: entries in one slot are the same dependency."""
    text: str
    """The canonical requirement, for display."""
    specifier: frozenset[Specifier] = frozenset()
    specifier_text: str = ""
    marker: str | None = None
    extras: tuple[str, ...] = ()
    url: str | None = None

    @property
    def identity(self) -> tuple[object, ...]:
        """Everything that makes two entries the same requirement.

        Returns:
            The comparable parts, with the specifiers as an unordered set.
        """
        return (self.slot, self.specifier, self.marker, self.extras, self.url)


def _parse_dependency(raw: str) -> _Dependency:
    """Canonicalize one requirement string.

    An unparsable entry is kept verbatim as its own slot: it cannot be
    matched semantically, but dropping it would hide a real difference.

    Returns:
        The comparable dependency.
    """
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        text = raw.strip()
        return _Dependency(text, text)
    name = canonicalize_name(requirement.name)
    extras = tuple(sorted(canonicalize_name(extra) for extra in requirement.extras))
    marker = str(requirement.marker) if requirement.marker else None
    gates = _gating_extras(marker)
    return _Dependency(
        slot=f"{name} (extra: {', '.join(gates)})" if gates else name,
        text=_requirement_text(
            name, extras, requirement.url or requirement.specifier, marker
        ),
        specifier=frozenset(requirement.specifier),
        specifier_text=str(requirement.specifier),
        marker=marker,
        extras=extras,
        url=requirement.url,
    )


def _gating_extras(marker: str | None) -> tuple[str, ...]:
    """Name every extra a marker gates on, canonicalized and sorted.

    Returns:
        The extras; empty when the entry is not extra-gated.
    """
    found = {
        canonicalize_name(match.group(1) or match.group(2))
        for match in _EXTRA_MARKER.finditer(marker or "")
    }
    return tuple(sorted(found))


def _requirement_text(
    name: str, extras: tuple[str, ...], version: SpecifierSet | str, marker: str | None
) -> str:
    """Spell a requirement in canonical PEP 508 form.

    Returns:
        ``name[extras]specifier; marker``, with ``@ url`` for a direct URL.
    """
    bracket = f"[{','.join(extras)}]" if extras else ""
    pin = f" @ {version}" if isinstance(version, str) else str(version)
    suffix = f"; {marker}" if marker else ""
    return f"{name}{bracket}{pin}{suffix}"


def _by_slot(raw: Iterable[str]) -> dict[str, list[_Dependency]]:
    slots: dict[str, list[_Dependency]] = {}
    for entry in raw:
        dependency = _parse_dependency(entry)
        slots.setdefault(dependency.slot, []).append(dependency)
    return slots


def _dependency_changes(before: list[str], after: list[str]) -> Iterator[Change]:
    a_slots, b_slots = _by_slot(before), _by_slot(after)
    for slot in sorted(a_slots.keys() | b_slots.keys()):
        yield from _slot_changes(slot, a_slots.get(slot, []), b_slots.get(slot, []))


def _slot_changes(
    slot: str, before: list[_Dependency], after: list[_Dependency]
) -> Iterator[Change]:
    """Diff one dependency slot.

    A slot with a single entry on each side is one dependency whose details
    changed. Several entries in a slot (one per marker branch, say) cannot be
    paired reliably, so they are diffed as sets of whole requirements.

    Yields:
        The slot's changes.
    """
    if len(before) == 1 and len(after) == 1:
        yield from _paired_changes(slot, before[0], after[0])
        return
    removed = Counter(d.identity for d in before) - Counter(d.identity for d in after)
    added = Counter(d.identity for d in after) - Counter(d.identity for d in before)
    for dependency in _take(before, removed):
        yield Change("dependencies", "dependency_removed", slot, dependency.text, None)
    for dependency in _take(after, added):
        yield Change("dependencies", "dependency_added", slot, None, dependency.text)


def _take(
    dependencies: list[_Dependency], counts: Counter[tuple[object, ...]]
) -> Iterator[_Dependency]:
    remaining = Counter(counts)
    for dependency in dependencies:
        if remaining[dependency.identity] > 0:
            remaining[dependency.identity] -= 1
            yield dependency


def _paired_changes(slot: str, a: _Dependency, b: _Dependency) -> Iterator[Change]:
    if a.identity == b.identity:
        return
    fields: tuple[tuple[ChangeKind, Value, Value], ...] = (
        ("dependency_specifier_changed", _spec_text(a), _spec_text(b)),
        ("dependency_marker_changed", a.marker, b.marker),
        ("dependency_extras_changed", list(a.extras), list(b.extras)),
    )
    changed: list[tuple[ChangeKind, Value, Value]] = [
        (kind, before, after)
        for (kind, before, after), differs in zip(
            fields,
            (a.specifier != b.specifier, a.marker != b.marker, a.extras != b.extras),
            strict=True,
        )
        if differs
    ]
    # Same specifier, marker and extras: only a direct URL moved. Report the
    # whole requirement so the difference is still visible.
    fallback: list[tuple[ChangeKind, Value, Value]] = [
        ("dependency_specifier_changed", a.text, b.text)
    ]
    for kind, before, after in changed or fallback:
        yield Change("dependencies", kind, slot, before, after)


def _spec_text(dependency: _Dependency) -> str:
    return dependency.specifier_text or "any"


def _extras(raw: Iterable[str]) -> set[str]:
    return {
        gate
        for entry in raw
        for gate in _gating_extras(_parse_dependency(entry).marker)
    }


def _extra_changes(before: list[str], after: list[str]) -> Iterator[Change]:
    """Report extras that appeared or disappeared.

    Derived from the markers that gate dependencies, since that is the
    evidence both sources carry; an extra that gates nothing is invisible.

    Yields:
        One change per extra added or removed.
    """
    a_extras, b_extras = _extras(before), _extras(after)
    for extra in sorted(a_extras - b_extras):
        yield Change("extras", "extra_removed", extra, extra, None)
    for extra in sorted(b_extras - a_extras):
        yield Change("extras", "extra_added", extra, None, extra)


# --- vulnerabilities ---------------------------------------------------------


def _vulnerability_changes(
    a: PackageInfo, b: PackageInfo, *, osv_skipped: bool
) -> list[Change] | Unknown:
    reason = _advisory_gap(a, b, osv_skipped=osv_skipped)
    if reason is not None:
        return Unknown("vulnerabilities", reason)
    changes: list[Change] = []
    for before, after in _advisory_groups(a.vulnerabilities, b.vulnerabilities):
        changes.extend(_advisory_change(before, after))
    return changes


def _advisory_gap(a: PackageInfo, b: PackageInfo, *, osv_skipped: bool) -> str | None:
    """Explain why one side's advisories cannot be compared, if it cannot.

    A skipped OSV lookup leaves a package read from the installed
    environment with no advisory source at all, so its empty list is absence
    of evidence, not a clean record. A package from PyPI still carries PyPI's
    own advisories, so skipping OSV does not make it unknown.

    Returns:
        The reason, or ``None`` when both sides can be compared.
    """
    failed = [pkg.name for pkg in (a, b) if pkg.vulnerabilities_unknown]
    if failed:
        return f"advisory lookup failed for {', '.join(failed)}"
    skipped = [pkg.name for pkg in (a, b) if osv_skipped and pkg.source == "local"]
    if skipped:
        return f"advisory lookup skipped for {', '.join(skipped)} (--no-osv)"
    return None


def _identifiers(vulnerability: Vulnerability) -> set[str]:
    return {vulnerability.id, *vulnerability.aliases}


@dataclass
class _AdvisoryGroup:
    """Every entry, on either side, that names the same advisory."""

    ids: set[str]
    before: list[Vulnerability]
    after: list[Vulnerability]


def _advisory_groups(
    before: list[Vulnerability], after: list[Vulnerability]
) -> Iterator[tuple[Vulnerability | None, Vulnerability | None]]:
    """Pair advisories across the two sides by id or any alias.

    Entries are grouped across *both* sides, transitively, before anything is
    compared. Pairing entry by entry would count one advisory twice whenever
    a side lists it under two aliases — reported as added, or its fix
    compared against the wrong record.

    Yields:
        One ``(before, after)`` pair per advisory, each merged across its
        aliases; ``None`` on the side that does not carry it.
    """
    groups: list[_AdvisoryGroup] = []
    for side, entries in ((0, before), (1, after)):
        for entry in entries:
            _add_to_groups(groups, entry, side)
    for group in groups:
        yield _merged(group.before), _merged(group.after)


def _add_to_groups(
    groups: list[_AdvisoryGroup], entry: Vulnerability, side: int
) -> None:
    """Add one entry, merging every group it links by id or alias.

    The merged group takes the place of the earliest group it absorbed, so
    advisories keep the order the sources listed them in.
    """
    ids = _identifiers(entry)
    linked = [index for index, group in enumerate(groups) if group.ids & ids]
    merged = _AdvisoryGroup(ids, [], [])
    for index in reversed(linked):
        group = groups.pop(index)
        merged.ids |= group.ids
        merged.before[:0] = group.before
        merged.after[:0] = group.after
    (merged.after if side else merged.before).append(entry)
    groups.insert(linked[0] if linked else len(groups), merged)


def _merged(entries: list[Vulnerability]) -> Vulnerability | None:
    """Fold one side's aliases of an advisory into a single record.

    Returns:
        The first entry, carrying every fixed version any alias names.
    """
    if not entries:
        return None
    fixed = list(dict.fromkeys(v for entry in entries for v in entry.fixed_in))
    return replace(entries[0], fixed_in=fixed)


def _advisory_change(
    before: Vulnerability | None, after: Vulnerability | None
) -> Iterator[Change]:
    if before is None and after is not None:
        yield _vulnerability_record("vulnerability_added", after)
    elif after is None and before is not None:
        yield _vulnerability_record("vulnerability_removed", before)
    elif before is not None and after is not None:
        yield from _fixed_in_changes(before, after)


def _vulnerability_value(vulnerability: Vulnerability) -> dict[str, object]:
    return {
        "summary": vulnerability.summary,
        "fixed_in": list(vulnerability.fixed_in),
        "severity": vulnerability.severity,
    }


def _vulnerability_record(
    kind: Literal["vulnerability_added", "vulnerability_removed"],
    vulnerability: Vulnerability,
) -> Change:
    value = _vulnerability_value(vulnerability)
    before, after = (None, value) if kind == "vulnerability_added" else (value, None)
    return Change("vulnerabilities", kind, vulnerability.id, before, after)


def _fixed_in_changes(a: Vulnerability, b: Vulnerability) -> Iterator[Change]:
    if {_version_key(v) for v in a.fixed_in} != {_version_key(v) for v in b.fixed_in}:
        yield Change(
            "vulnerabilities",
            "vulnerability_fixed_in_changed",
            a.id,
            list(a.fixed_in),
            list(b.fixed_in),
        )


# --- artifacts ---------------------------------------------------------------

_ARTIFACT_GROUPS: tuple[ChangeGroup, ...] = ("artifacts", "provenance")

_SDIST_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar")
"""Archive formats, longest first so ``.tar.gz`` is not read as ``.tar``."""


def _artifact_side_changes(
    a: ReleaseEvidence, b: ReleaseEvidence
) -> list[Change] | Unknown:
    if a.release is None or b.release is None:
        # Deduplicated: comparing a release with itself would otherwise
        # state the same reason twice.
        reasons = dict.fromkeys(side.reason for side in (a, b) if side.reason)
        return Unknown(
            "artifacts", "; ".join(reasons) or "artifact listing unavailable"
        )
    return [
        *_release_date_changes(a.release, b.release),
        *_artifact_changes(a.release, b.release),
    ]


def _release_date(release: ReleaseArtifacts) -> str | None:
    """Date a release by its first upload, which is when it was published.

    Returns:
        The earliest ``YYYY-MM-DD`` upload date, or ``None`` if none is known.
    """
    dates = [f.upload_time[:10] for f in release.files if f.upload_time]
    return min(dates, default=None)


def _release_date_changes(a: ReleaseArtifacts, b: ReleaseArtifacts) -> Iterator[Change]:
    before, after = _release_date(a), _release_date(b)
    if before != after:
        yield Change("release", "release_date_changed", "release_date", before, after)


def _slot(file: ArtifactFile) -> str:
    """Name the role a file plays, so two releases' files can be paired.

    Filenames embed the version, so ``django-5.2`` and ``django-6.0`` share no
    filename; what they share is the slot — a wheel for the same tags, or the
    source distribution in the same archive format. The format is part of the
    slot because older projects publish both ``.tar.gz`` and ``.zip``, and one
    shared slot would pair whichever the index listed first.

    Returns:
        The file's slot.
    """
    if file.kind == "wheel" and file.tags:
        return f"wheel {'.'.join(sorted(file.tags))}"
    if file.kind == "sdist":
        suffix = next(
            (s for s in _SDIST_SUFFIXES if file.filename.lower().endswith(s)), ""
        )
        return f"sdist {suffix}".rstrip()
    return file.filename


def _by_artifact_slot(files: list[ArtifactFile]) -> dict[str, ArtifactFile]:
    slots: dict[str, ArtifactFile] = {}
    for file in files:
        slot = _slot(file)
        slots[file.filename if slot in slots else slot] = file
    return slots


def _artifact_changes(a: ReleaseArtifacts, b: ReleaseArtifacts) -> Iterator[Change]:
    a_slots, b_slots = _by_artifact_slot(a.files), _by_artifact_slot(b.files)
    for slot in sorted(a_slots.keys() | b_slots.keys()):
        before, after = a_slots.get(slot), b_slots.get(slot)
        if before is None or after is None:
            yield _presence_change(slot, before, after)
            continue
        yield from _file_changes(slot, before, after)


def _presence_change(
    slot: str, before: ArtifactFile | None, after: ArtifactFile | None
) -> Change:
    if before is None:
        return Change("artifacts", "artifact_added", slot, None, _filename(after))
    return Change("artifacts", "artifact_removed", slot, before.filename, None)


def _filename(file: ArtifactFile | None) -> str | None:
    return file.filename if file else None


def _file_changes(slot: str, a: ArtifactFile, b: ArtifactFile) -> Iterator[Change]:
    """Diff two files occupying the same slot.

    Digests and sizes are expected to differ between two different files —
    every new release has new ones — so they are flagged as expected unless
    the filename is the same. Under one filename they are the case that
    matters: a file re-uploaded under a name that was already published.

    Yields:
        The slot's changes.
    """
    expected = a.filename != b.filename
    per_file: tuple[tuple[ChangeKind, Value, Value], ...] = (
        ("artifact_hash_changed", a.sha256, b.sha256),
        ("artifact_size_changed", a.size, b.size),
    )
    for kind, before, after in per_file:
        if before != after:
            yield Change("artifacts", kind, slot, before, after, expected=expected)
    fields: tuple[tuple[ChangeGroup, ChangeKind, Value, Value], ...] = (
        ("artifacts", "artifact_yanked_changed", a.yanked, b.yanked),
        (
            "artifacts",
            "artifact_compatibility_changed",
            a.compatibility.compatible,
            b.compatibility.compatible,
        ),
        (
            "provenance",
            "provenance_changed",
            a.provenance_url is not None,
            b.provenance_url is not None,
        ),
    )
    for group, kind, before, after in fields:
        if before != after:
            yield Change(group, kind, slot, before, after)
