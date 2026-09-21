"""Plain-text output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from peta.cli.output.summary import (
    file_flags,
    file_publishers,
    file_size,
    summary_rows,
    verdict,
)

if TYPE_CHECKING:
    from peta.core.artifacts import ReleaseArtifacts
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


def _value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        items = cast("list[object]", value)
        return ", ".join(str(item) for item in items) or "-"
    return str(value).replace("\n", " ")


def _security_lines(pkg: PackageInfo) -> list[str]:
    lines: list[str] = []
    if pkg.vulnerabilities:
        lines.extend(["", "Vulnerabilities:"])
        for vulnerability in pkg.vulnerabilities:
            severity = f" [{vulnerability.severity}]" if vulnerability.severity else ""
            fixed = ", ".join(vulnerability.fixed_in) or "no known fix"
            description = f"{vulnerability.summary} (fix: {fixed})"
            lines.append(f"- {vulnerability.id}{severity}: {description}")
    lines.extend(_warning_lines(pkg))
    return lines


def _warning_lines(*packages: PackageInfo) -> list[str]:
    prefixed = len(packages) > 1

    def owner(name: str) -> str:
        return f"{name}: " if prefixed else ""

    warnings = [
        f"- {owner(pkg.name)}{failure.source}: {failure.reason}"
        for pkg in packages
        for failure in pkg.enrichment_failures
    ]
    warnings.extend(
        f"- {owner(pkg.name)}{conflict.field}: {conflict.description}"
        for pkg in packages
        for conflict in pkg.enrichment_conflicts
    )
    warnings.extend(
        f"- {owner(pkg.name)}{w.source}: {w.message}"
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


def format_compare(a: PackageInfo, b: PackageInfo) -> str:
    """Format a package comparison as tab-separated text.

    Returns:
        A header and one tab-separated row per field.
    """
    rows = [
        ("Version", a.version, b.version),
        ("Source", a.source, b.source),
        ("License", a.license, b.license),
        ("Requires Python", a.python_requires, b.python_requires),
        ("Dependencies", a.dependencies, b.dependencies),
        ("Vulnerabilities", _vulnerability_count(a), _vulnerability_count(b)),
    ]
    lines = [f"Field\t{a.name}\t{b.name}"]
    lines.extend(
        f"{field}\t{_value(a_value)}\t{_value(b_value)}"
        for field, a_value, b_value in rows
    )
    lines.extend(_warning_lines(a, b))
    return "\n".join(lines)


def _tree_lines(node: DependencyNode, depth: int = 0) -> list[str]:
    suffix = f" {node.version_spec}" if node.version_spec else ""
    state = f" ({node.state.replace('_', ' ')})" if node.state != "satisfied" else ""
    selected = f" (selected {node.selected_version})" if node.selected_version else ""
    failure = node.resolution_failure
    unresolved = f" (unresolved: {failure.reason})" if failure else ""
    lines = [f"{'  ' * depth}{node.name}{suffix}{selected}{state}{unresolved}"]
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
    lines = [f"Why {target}?"]
    lines.extend(" -> ".join(path) for path in paths)
    return "\n".join(lines)


def format_files(pkg: PackageInfo) -> str:
    """Format installed files as plain text.

    Returns:
        A heading and one path per line.
    """
    return "\n".join([f"Files for {pkg.name} {pkg.version}", *(pkg.files or [])])


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format published versions as tab-separated text.

    Returns:
        A heading and one version per line.
    """
    lines = [f"Versions for {name}", "Version\tUploaded"]
    lines.extend(f"{item['version']}\t{item['upload_time']}" for item in versions)
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
    lines = [f"Artifacts for {release.name} {release.version}"]
    lines.extend(f"{label}: {value}" for label, value in summary_rows(release))
    if detailed and release.files:
        lines.extend(["", "\t".join(_ARTIFACT_COLUMNS)])
        lines.extend(
            "\t".join([
                file.filename,
                file.kind,
                file_size(file),
                file.upload_time or "-",
                file.requires_python or "-",
                verdict(file),
                file.sha256 or "-",
                file_flags(file),
                file_publishers(file),
            ])
            for file in release.files
        )
    lines.extend(_artifact_notes(release))
    return "\n".join(lines)


def _artifact_notes(release: ReleaseArtifacts) -> list[str]:
    """Report incompatibility reasons, yanks, and failed provenance lookups.

    Returns:
        Trailing note lines, empty when there is nothing to report.
    """
    notes = [
        f"- {file.filename}: {file.compatibility.reason}"
        for file in release.files
        if file.compatibility.reason
    ]
    notes.extend(
        f"- {file.filename} yanked: {file.yanked_reason or 'no reason given'}"
        for file in release.files
        if file.yanked
    )
    notes.extend(
        f"- provenance lookup failed: {f.description}"
        for f in release.publisher_failures
    )
    if not notes:
        return []
    return ["", "Notes:", *notes]
