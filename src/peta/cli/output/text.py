"""Plain-text output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from peta.cli.output.changes import sections
from peta.cli.output.console import inline
from peta.cli.output.summary import (
    file_flags,
    file_publishers,
    file_size,
    summary_rows,
    verdict,
)
from peta.core.diff import diff_packages

if TYPE_CHECKING:
    from peta.core.artifacts import ArtifactFile, ReleaseArtifacts
    from peta.core.changes import ChangeSet
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "format_artifacts",
    "format_compare",
    "format_dep_tree",
    "format_files",
    "format_info",
    "format_versions",
    "format_why",
]


def _field(value: object) -> str:
    """Render one untrusted value so it cannot add lines or columns.

    This formatter is line-oriented and its tables are tab-separated, so a
    newline or tab inside a value — a yank reason, a filename, a summary —
    would forge an extra line or column. :func:`inline` folds both to spaces,
    which is how a wrapped summary has always been shown here.

    Returns:
        The value on one line, with terminal control characters removed.
    """
    return inline(value)


def _value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        items = cast("list[object]", value)
        return ", ".join(_field(item) for item in items) or "-"
    return _field(value)


def _security_lines(pkg: PackageInfo) -> list[str]:
    lines: list[str] = []
    if pkg.vulnerabilities:
        lines.extend(["", "Vulnerabilities:"])
        for vulnerability in pkg.vulnerabilities:
            severity = (
                f" [{_field(vulnerability.severity)}]" if vulnerability.severity else ""
            )
            fixed = _value(vulnerability.fixed_in) if vulnerability.fixed_in else ""
            description = (
                f"{_value(vulnerability.summary)} (fix: {fixed or 'no known fix'})"
            )
            lines.append(f"- {_field(vulnerability.id)}{severity}: {description}")
    lines.extend(_warning_lines(pkg))
    return lines


def _warning_lines(*packages: PackageInfo) -> list[str]:
    prefixed = len(packages) > 1

    def owner(name: str) -> str:
        return f"{_field(name)}: " if prefixed else ""

    warnings = [
        f"- {owner(pkg.name)}{_field(failure.source)}: {_field(failure.reason)}"
        for pkg in packages
        for failure in pkg.enrichment_failures
    ]
    warnings.extend(
        f"- {owner(pkg.name)}{_field(conflict.field)}: {_field(conflict.description)}"
        for pkg in packages
        for conflict in pkg.enrichment_conflicts
    )
    warnings.extend(
        f"- {owner(pkg.name)}{_field(w.source)}: {_field(w.message)}"
        for pkg in packages
        for w in pkg.provider_warnings
    )
    if not warnings:
        return []
    return ["", "Enrichment warnings:", *warnings]


def format_info(pkg: PackageInfo) -> str:
    """Format package metadata as plain text.

    Returns:
        One labeled field per line.
    """
    rows = [
        ("Name", pkg.name),
        ("Version", pkg.version),
        ("Source", pkg.source),
        ("Summary", pkg.summary),
        ("License", pkg.license),
        ("Requires Python", pkg.python_requires),
        ("Homepage", pkg.homepage),
        ("Dependencies", pkg.dependencies),
        ("Downloads", pkg.download_count),
        ("Dependents", pkg.dependent_count),
    ]
    lines = [f"{label}: {_value(value)}" for label, value in rows]
    lines.extend(_security_lines(pkg))
    return "\n".join(lines)


def _vulnerability_count(pkg: PackageInfo) -> str:
    if pkg.vulnerabilities_unknown:
        return "unknown"
    return str(len(pkg.vulnerabilities))


def _change_lines(diff: ChangeSet) -> list[str]:
    """List a diff's changes, grouped, with unchanged groups left out.

    Returns:
        A heading followed by one indented line per change.
    """
    groups = sections(diff, arrow="->")
    if not groups:
        return ["Changes: none"]
    lines = ["Changes:"]
    for section in groups:
        lines.append(f"{section.title}:")
        if section.unknown:
            lines.append(f"  ? unknown: {_field(section.unknown)}")
        lines.extend(
            f"  {line.symbol} {_field(line.subject)}"
            + (f": {_field(line.detail)}" if line.detail else "")
            for line in section.lines
        )
        if section.expected_note:
            lines.append(f"  · {section.expected_note}")
    return lines


def format_compare(
    a: PackageInfo,
    b: PackageInfo,
    diff: ChangeSet | None = None,
    *,
    changes_only: bool = False,
) -> str:
    """Format a package comparison as tab-separated text.

    Returns:
        A header and one tab-separated row per field, then the grouped
        semantic changes; only the changes with ``changes_only``.
    """
    changes = _change_lines(diff or diff_packages(a, b))
    if changes_only:
        title = (
            f"{_field(a.name)} {_field(a.version)} -> "
            f"{_field(b.name)} {_field(b.version)}"
        )
        return "\n".join([title, *changes, *_warning_lines(a, b)])
    rows = [
        ("Version", a.version, b.version),
        ("Source", a.source, b.source),
        ("License", a.license, b.license),
        ("Requires Python", a.python_requires, b.python_requires),
        ("Dependencies", a.dependencies, b.dependencies),
        ("Vulnerabilities", _vulnerability_count(a), _vulnerability_count(b)),
    ]
    lines = [f"Field\t{_field(a.name)}\t{_field(b.name)}"]
    lines.extend(
        f"{field}\t{_value(a_value)}\t{_value(b_value)}"
        for field, a_value, b_value in rows
    )
    lines.extend(["", *changes])
    lines.extend(_warning_lines(a, b))
    return "\n".join(lines)


def _tree_lines(node: DependencyNode, depth: int = 0) -> list[str]:
    suffix = f" {_field(node.version_spec)}" if node.version_spec else ""
    state = (
        f" ({node.state.replace('_', ' ')})"
        if node.state != "satisfied" and node.resolution_failure is None
        else ""
    )
    selected = (
        f" (selected {_field(node.selected_version)})" if node.selected_version else ""
    )
    failure = node.resolution_failure
    unresolved = f" (unresolved: {_field(failure.reason)})" if failure else ""
    lines = [f"{'  ' * depth}{_field(node.name)}{suffix}{selected}{state}{unresolved}"]
    for child in node.children:
        lines.extend(_tree_lines(child, depth + 1))
    return lines


def format_dep_tree(node: DependencyNode) -> str:
    """Format a dependency tree as indented plain text.

    Returns:
        One dependency per line.
    """
    return "\n".join(["Declared metadata tree:", *_tree_lines(node)])


def format_why(target: str, paths: list[list[str]]) -> str:
    """Format dependency paths as plain text.

    Returns:
        A heading and one path per line.
    """
    lines = [f"Why {_field(target)}?"]
    lines.extend(" -> ".join(_field(name) for name in path) for path in paths)
    return "\n".join(lines)


def format_files(pkg: PackageInfo) -> str:
    """Format installed files as plain text.

    Returns:
        A heading and one path per line.
    """
    return "\n".join([
        f"Files for {_field(pkg.name)} {_field(pkg.version)}",
        *(_field(path) for path in pkg.files or []),
    ])


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format published versions as tab-separated text.

    Returns:
        A heading and one version per line.
    """
    lines = [f"Versions for {_field(name)}", "Version\tUploaded"]
    lines.extend(
        f"{_field(item['version'])}\t{_field(item['upload_time'])}" for item in versions
    )
    return "\n".join(lines)


_ARTIFACT_COLUMNS = (
    "File",
    "Kind",
    "Size",
    "Uploaded",
    "Requires",
    "Compatible",
    "SHA-256",
    "Flags",
    "Published by",
)


def format_artifacts(release: ReleaseArtifacts, *, detailed: bool = False) -> str:
    """Format a release's artifacts as plain text.

    Unlike the Rich view this carries the full SHA-256 of every file, since
    plain text is what a script or a reviewer pipes somewhere else.

    Returns:
        A summary block, an optional tab-separated file table, and any notes.
    """
    lines = [f"Artifacts for {_field(release.name)} {_field(release.version)}"]
    lines.extend(f"{label}: {_field(value)}" for label, value in summary_rows(release))
    if detailed and release.files:
        lines.extend(["", "\t".join(_ARTIFACT_COLUMNS)])
        lines.extend(
            "\t".join(
                _field(column)
                for column in (
                    file.filename,
                    file.kind,
                    file_size(file),
                    file.upload_time or "-",
                    file.requires_python or "-",
                    verdict(file),
                    file.sha256 or "-",
                    file_flags(file),
                    file_publishers(file),
                )
            )
            for file in release.files
        )
    lines.extend(_artifact_notes(release))
    return "\n".join(lines)


def _yanked_reason(file: ArtifactFile) -> str:
    """Render a yank reason, naming the absence of one explicitly.

    Returns:
        The reason PyPI recorded, or a stand-in when it recorded none.
    """
    return _field(file.yanked_reason or "no reason given")


def _artifact_notes(release: ReleaseArtifacts) -> list[str]:
    """Report incompatibility reasons, yanks, and failed provenance lookups.

    Returns:
        Trailing note lines, empty when there is nothing to report.
    """
    notes = [
        f"- {_field(file.filename)}: {_field(file.compatibility.reason)}"
        for file in release.files
        if file.compatibility.reason
    ]
    notes.extend(
        f"- {_field(file.filename)} yanked: {_yanked_reason(file)}"
        for file in release.files
        if file.yanked
    )
    notes.extend(
        f"- provenance lookup failed: {_field(f.description)}"
        for f in release.publisher_failures
    )
    if not notes:
        return []
    return ["", "Notes:", *notes]
