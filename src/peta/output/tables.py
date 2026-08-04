"""Rich text output formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from peta.output.console import render as _render

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["render_deps", "render_files", "render_info", "render_versions"]


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
    _add_dependency_rows(table, pkg)
    return table


def _vuln_block(pkg: PackageInfo) -> str:
    if not pkg.vulnerabilities:
        return ""
    lines = ["\n⚠ Vulnerabilities:"]
    for v in pkg.vulnerabilities:
        fixed = ", ".join(v.fixed_in) if v.fixed_in else "no fix"
        lines.append(f"  {v.id}: {v.summary} (fix: {fixed})")
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


def render_deps(pkg: PackageInfo, *, color: bool) -> str:
    """Render a package's dependencies as a Rich tree string.

    Returns:
        The dependency tree rendered as text.
    """
    tree = Tree(f"{pkg.name} {pkg.version}")
    for dep in pkg.dependencies:
        _ = tree.add(dep)
    return _to_string(tree, color=color)


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
