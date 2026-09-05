"""Plain-text output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from peta.core.models import DependencyNode, PackageInfo, ProviderConflict

__all__ = [
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


def _conflict_reason(conflict: ProviderConflict) -> str:
    return f"kept {conflict.kept}, discarded conflicting {conflict.discarded}"


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
        f"- {owner(pkg.name)}{conflict.field}: {_conflict_reason(conflict)}"
        for pkg in packages
        for conflict in pkg.enrichment_conflicts
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
    circular = " (circular)" if node.circular else ""
    installed = (
        f" (installed {node.installed_version})" if node.installed_version else ""
    )
    failure = node.resolution_failure
    unresolved = f" (unresolved: {failure.reason})" if failure else ""
    lines = [f"{'  ' * depth}{node.name}{suffix}{circular}{installed}{unresolved}"]
    for child in node.children:
        lines.extend(_tree_lines(child, depth + 1))
    return lines


def format_dep_tree(node: DependencyNode) -> str:
    """Format a dependency tree as indented plain text.

    Returns:
        One dependency per line.
    """
    return "\n".join(_tree_lines(node))


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
