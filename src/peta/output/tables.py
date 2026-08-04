"""Rich text output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from peta.output.console import render as _render

if TYPE_CHECKING:
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "render_compare",
    "render_dep_tree",
    "render_files",
    "render_info",
    "render_versions",
    "render_why",
]


def _to_string(renderable: object, *, color: bool) -> str:
    return _render(renderable, color=color)


def _add_optional_rows(table: Table, pkg: PackageInfo) -> None:
    for label, value in (
        ("Summary", pkg.summary),
        ("Author", pkg.author),
        ("Maintainer", pkg.maintainer),
        ("License", pkg.license),
        ("Python", pkg.python_requires),
        ("Homepage", pkg.homepage),
    ):
        if value:
            table.add_row(label, value)
    for url_label, url in pkg.project_urls.items():
        table.add_row(f"  {url_label}", url)


def _add_stats_rows(table: Table, pkg: PackageInfo) -> None:
    if pkg.download_count is not None:
        table.add_row("Downloads (last month)", f"{pkg.download_count:,}")
    if pkg.dependent_count is not None:
        table.add_row("Dependents", f"{pkg.dependent_count:,}")


def _add_dependency_rows(table: Table, pkg: PackageInfo) -> None:
    if not pkg.dependencies:
        return
    table.add_row("Dependencies", str(len(pkg.dependencies)))
    for dep in pkg.dependencies:
        table.add_row("", f"  {dep}")


def _info_table(pkg: PackageInfo) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    table.add_row("Name", pkg.name)
    table.add_row("Version", pkg.version)
    _add_optional_rows(table, pkg)
    _add_stats_rows(table, pkg)
    _add_dependency_rows(table, pkg)
    return table


def _vuln_block(pkg: PackageInfo) -> str:
    if not pkg.vulnerabilities:
        return ""
    lines = ["\n⚠ Vulnerabilities:"]
    for v in pkg.vulnerabilities:
        fixed = ", ".join(v.fixed_in) if v.fixed_in else "no fix"
        severity = f" [{v.severity}]" if v.severity else ""
        lines.append(f"  {v.id}{severity}: {v.summary} (fix: {fixed})")
    return "\n".join(lines) + "\n"


def render_info(pkg: PackageInfo, *, color: bool) -> str:
    """Render :class:`PackageInfo` as a Rich panel string.

    Returns:
        The formatted panel text, with any vulnerability block appended.
    """
    source_label = "local" if pkg.source == "local" else "pypi"
    panel = Panel(
        _info_table(pkg),
        title=f"{pkg.name} {pkg.version}",
        subtitle=f"source: {source_label}",
    )
    return _to_string(panel, color=color) + _vuln_block(pkg)


def _node_label(node: DependencyNode) -> str:
    if node.circular:
        return f"{node.name} (circular)"
    label = f"{node.name} {node.version_spec}".rstrip()
    if node.installed_version:
        label += f" (installed {node.installed_version})"
    return label


def _add_children(branch: Tree, node: DependencyNode) -> None:
    for child in node.children:
        _add_children(branch.add(_node_label(child)), child)


def render_dep_tree(node: DependencyNode, *, color: bool) -> str:
    """Render a recursive dependency tree as a Rich tree string.

    Returns:
        The dependency tree rendered as text.
    """
    root_label = f"{node.name} {node.installed_version}".rstrip()
    tree = Tree(root_label)
    _add_children(tree, node)
    return _to_string(tree, color=color)


def render_why(target: str, paths: list[list[str]], *, color: bool) -> str:
    """Render root-to-target dependency chains as arrow-joined lines.

    ``color`` is accepted for signature parity with the other renderers but
    unused: this output is plain lines, not a Rich renderable.

    Returns:
        Each path rendered as ``a -> b -> target``, one per line.
    """
    del color
    if not paths:
        return f"'{target}' is not a dependency.\n"
    return "\n".join(" → ".join(path) for path in paths) + "\n"


def render_files(pkg: PackageInfo, *, color: bool) -> str:
    """Render a package's file listing as a string.

    ``color`` is accepted for signature parity with the other renderers but
    unused: this output is plain lines, not a Rich renderable.

    Returns:
        The file listing rendered as text.
    """
    del color
    if not pkg.files:
        return f"No file information available for {pkg.name}.\n"
    lines = [f"{pkg.name} {pkg.version} ({len(pkg.files)} files)\n"]
    lines.extend(f"  {f}" for f in pkg.files)
    return "\n".join(lines) + "\n"


def _compare_rows(a: PackageInfo, b: PackageInfo) -> list[tuple[str, str, str]]:
    def count_or_dash(value: int | None) -> str:
        return "-" if value is None else f"{value:,}"

    fields: list[tuple[str, str, str]] = [
        ("Version", a.version, b.version),
        ("Summary", a.summary or "-", b.summary or "-"),
        ("Author", a.author or "-", b.author or "-"),
        ("License", a.license or "-", b.license or "-"),
        ("Python", a.python_requires or "-", b.python_requires or "-"),
        ("Dependencies", str(len(a.dependencies)), str(len(b.dependencies))),
        ("Downloads", count_or_dash(a.download_count), count_or_dash(b.download_count)),
        (
            "Dependents",
            count_or_dash(a.dependent_count),
            count_or_dash(b.dependent_count),
        ),
        ("Vulnerabilities", str(len(a.vulnerabilities)), str(len(b.vulnerabilities))),
    ]
    return fields


def render_compare(a: PackageInfo, b: PackageInfo, *, color: bool) -> str:
    """Render two :class:`PackageInfo` objects as a side-by-side Rich table.

    Returns:
        The comparison table rendered as text.
    """
    table = Table(title=f"{a.name} vs {b.name}")
    table.add_column("Field", style="bold cyan")
    table.add_column(a.name)
    table.add_column(b.name)
    for label, a_value, b_value in _compare_rows(a, b):
        table.add_row(label, a_value, b_value)
    return _to_string(table, color=color)


def render_versions(name: str, versions: list[dict[str, str]], *, color: bool) -> str:
    """Render a version list as a Rich table string.

    Returns:
        The version table rendered as text.
    """
    table = Table(title=f"{name} versions ({len(versions)} shown)")
    table.add_column("Version", style="bold")
    table.add_column("Released")
    for v in versions:
        table.add_row(v["version"], v.get("upload_time", ""))
    return _to_string(table, color=color)
