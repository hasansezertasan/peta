"""Central dispatch for CLI output representations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from peta.cli.output import json, markdown, tables, text
from peta.cli.output.selection import OutputFormat

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


def render_info(
    output_format: OutputFormat,
    pkg: PackageInfo,
    *,
    arguments: dict[str, object],
    color: bool,
) -> str:
    """Render package information in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_info(pkg, arguments=arguments)
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_info(pkg)
    if output_format == OutputFormat.TEXT:
        return text.format_info(pkg)
    return tables.render_info(pkg, color=color)


def render_compare(
    output_format: OutputFormat,
    a: PackageInfo,
    b: PackageInfo,
    *,
    arguments: dict[str, object],
    color: bool,
) -> str:
    """Render a package comparison in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_compare(a, b, arguments=arguments)
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_compare(a, b)
    if output_format == OutputFormat.TEXT:
        return text.format_compare(a, b)
    return tables.render_compare(a, b, color=color)


def render_dep_tree(
    output_format: OutputFormat,
    tree: DependencyNode,
    *,
    arguments: dict[str, object],
    color: bool,
) -> str:
    """Render a dependency tree in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_dep_tree(tree, arguments=arguments)
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_dep_tree(tree)
    if output_format == OutputFormat.TEXT:
        return text.format_dep_tree(tree)
    return tables.render_dep_tree(tree, color=color)


def render_why(
    output_format: OutputFormat,
    target: str,
    paths: list[list[str]],
    tree: DependencyNode,
    *,
    arguments: dict[str, object],
    color: bool,
) -> str:
    """Render dependency paths in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_why(target, paths, arguments=arguments, tree=tree)
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_why(target, paths)
    if output_format == OutputFormat.TEXT:
        return text.format_why(target, paths)
    return tables.render_why(target, paths, color=color)


def render_files(
    output_format: OutputFormat,
    pkg: PackageInfo,
    *,
    arguments: dict[str, object],
    color: bool,
) -> str:
    """Render installed files in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_files(pkg, arguments=arguments)
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_files(pkg)
    if output_format == OutputFormat.TEXT:
        return text.format_files(pkg)
    return tables.render_files(pkg, color=color)


def render_versions(
    output_format: OutputFormat,
    package: str,
    versions: list[dict[str, str]],
    *,
    arguments: dict[str, object],
    color: bool,
    retrieved_at: str,
) -> str:
    """Render published versions in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_versions(
            package, versions, arguments=arguments, retrieved_at=retrieved_at
        )
    if output_format == OutputFormat.MARKDOWN:
        return markdown.format_versions(package, versions)
    if output_format == OutputFormat.TEXT:
        return text.format_versions(package, versions)
    return tables.render_versions(package, versions, color=color)
