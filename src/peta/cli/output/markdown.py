"""Markdown output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "format_compare",
    "format_dep_tree",
    "format_files",
    "format_info",
    "format_versions",
    "format_why",
]


def _cell(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, list):
        items = cast("list[object]", value)
        return ", ".join(str(item) for item in items) or "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _security_lines(pkg: PackageInfo) -> list[str]:
    lines: list[str] = []
    if pkg.vulnerabilities:
        lines.extend(["", "## Vulnerabilities", ""])
        for vulnerability in pkg.vulnerabilities:
            severity = (
                f" ({_cell(vulnerability.severity)})" if vulnerability.severity else ""
            )
            fixed = ", ".join(
                f"`{_cell(version)}`" for version in vulnerability.fixed_in
            )
            fix_text = fixed or "no known fix"
            description = f"{_cell(vulnerability.summary)} (fix: {fix_text})"
            lines.append(f"- `{_cell(vulnerability.id)}`{severity}: {description}")
    lines.extend(_warning_lines(pkg))
    return lines


def _warning_lines(*packages: PackageInfo) -> list[str]:
    failures = [
        (pkg.name, failure) for pkg in packages for failure in pkg.enrichment_failures
    ]
    if not failures:
        return []
    prefixed = len(packages) > 1

    def item(name: str, source: str, reason: str) -> str:
        owner = f"`{_cell(name)}` — " if prefixed else ""
        return f"- {owner}**{_cell(source)}:** {_cell(reason)}"

    return [
        "",
        "## Enrichment warnings",
        "",
        *(item(name, failure.source, failure.reason) for name, failure in failures),
    ]


def _vulnerability_count(pkg: PackageInfo) -> str:
    if any(failure.source == "osv" for failure in pkg.enrichment_failures):
        return "unknown"
    return str(len(pkg.vulnerabilities))


def format_info(pkg: PackageInfo) -> str:
    """Format package metadata as Markdown.

    Returns:
        A Markdown heading and field table.
    """
    rows = [
        ("Source", pkg.source),
        ("Summary", pkg.summary),
        ("License", pkg.license),
        ("Requires Python", pkg.python_requires),
        ("Homepage", pkg.homepage),
        ("Dependencies", pkg.dependencies),
        ("Downloads", pkg.download_count),
        ("Dependents", pkg.dependent_count),
    ]
    lines = [f"# {pkg.name} {pkg.version}", "", "| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {name} | {_cell(value)} |" for name, value in rows)
    lines.extend(_security_lines(pkg))
    return "\n".join(lines)


def format_compare(a: PackageInfo, b: PackageInfo) -> str:
    """Format a package comparison as Markdown.

    Returns:
        A Markdown comparison table.
    """
    rows = [
        ("Version", a.version, b.version),
        ("Source", a.source, b.source),
        ("License", a.license, b.license),
        ("Requires Python", a.python_requires, b.python_requires),
        ("Dependencies", a.dependencies, b.dependencies),
        ("Vulnerabilities", _vulnerability_count(a), _vulnerability_count(b)),
    ]
    lines = [
        "# Package comparison",
        "",
        f"| Field | {_cell(a.name)} | {_cell(b.name)} |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| {field} | {_cell(a_value)} | {_cell(b_value)} |"
        for field, a_value, b_value in rows
    )
    lines.extend(_warning_lines(a, b))
    return "\n".join(lines)


def _tree_lines(node: DependencyNode, depth: int = 0) -> list[str]:
    suffix = f" {node.version_spec}" if node.version_spec else ""
    circular = " _(circular)_" if node.circular else ""
    installed = (
        f" _(installed {_cell(node.installed_version)})_"
        if node.installed_version
        else ""
    )
    failure = node.resolution_failure
    unresolved = f" _(unresolved: {_cell(failure.reason)})_" if failure else ""
    lines = [f"{'  ' * depth}- `{node.name}{suffix}`{circular}{installed}{unresolved}"]
    for child in node.children:
        lines.extend(_tree_lines(child, depth + 1))
    return lines


def format_dep_tree(node: DependencyNode) -> str:
    """Format a dependency tree as Markdown.

    Returns:
        A heading and nested Markdown list.
    """
    return "\n".join([f"# Dependencies for {node.name}", "", *_tree_lines(node)])


def format_why(target: str, paths: list[list[str]]) -> str:
    """Format dependency paths as Markdown.

    Returns:
        A heading and one list item per path.
    """
    lines = [f"# Why {target}?", ""]
    lines.extend(f"- {' → '.join(f'`{name}`' for name in path)}" for path in paths)
    return "\n".join(lines)


def format_files(pkg: PackageInfo) -> str:
    """Format an installed file list as Markdown.

    Returns:
        A heading and Markdown list.
    """
    lines = [f"# Files for {pkg.name} {pkg.version}", ""]
    lines.extend(f"- `{path}`" for path in pkg.files or [])
    return "\n".join(lines)


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format published versions as Markdown.

    Returns:
        A heading and Markdown table.
    """
    lines = [f"# Versions for {name}", "", "| Version | Uploaded |", "| --- | --- |"]
    lines.extend(
        f"| {_cell(item['version'])} | {_cell(item['upload_time'])} |"
        for item in versions
    )
    return "\n".join(lines)
