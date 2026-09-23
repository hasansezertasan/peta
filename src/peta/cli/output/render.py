"""Central dispatch for CLI output representations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from peta.cli.output import json, markdown, tables, text
from peta.cli.output.console import sanitize_terminal
from peta.cli.output.selection import OutputFormat

if TYPE_CHECKING:
    from peta.core.artifacts import ReleaseArtifacts
    from peta.core.cache import Freshness
    from peta.core.local import LocalTarget
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "render_artifacts",
    "render_compare",
    "render_dep_tree",
    "render_files",
    "render_info",
    "render_target",
    "render_versions",
    "render_why",
]


def _plain_output(value: str) -> str:
    """Make the plain-text renderers safe to paste into a terminal.

    Text and Markdown carry no styling of peta's own, so the finished string
    can be hardened wholesale. The Rich renderers cannot: their output is
    mostly escape sequences peta itself emitted, so they are hardened per
    rendered segment inside :func:`peta.cli.output.console.render`.

    Credentials are not this function's business. They are stripped where a
    diagnostic is built, so that a URL a package merely *declared* is reported
    as declared rather than quietly rewritten.

    Returns:
        The rendered value with terminal control characters removed.
    """
    return sanitize_terminal(value)


def render_target(target: LocalTarget) -> str:
    """Render the target-environment banner shown above human output.

    Printed outside the formatters, so it would otherwise skip the one
    boundary every other human string passes through. It names paths from
    ``--path`` and from the target interpreter's own ``sys.path``, and a
    directory name can carry an escape sequence like any other untrusted text.

    Returns:
        The banner with terminal control characters removed.
    """
    return _plain_output(target.describe())


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
        return _plain_output(markdown.format_info(pkg))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_info(pkg))
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
        return _plain_output(markdown.format_compare(a, b))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_compare(a, b))
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
        return _plain_output(markdown.format_dep_tree(tree))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_dep_tree(tree))
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
        return _plain_output(markdown.format_why(target, paths))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_why(target, paths))
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
        return _plain_output(markdown.format_files(pkg))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_files(pkg))
    return tables.render_files(pkg, color=color)


def render_versions(
    output_format: OutputFormat,
    package: str,
    versions: list[dict[str, str]],
    *,
    arguments: dict[str, object],
    color: bool,
    retrieved_at: str,
    freshness: Freshness | None = None,
) -> str:
    """Render published versions in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_versions(
            package,
            versions,
            arguments=arguments,
            retrieved_at=retrieved_at,
            freshness=freshness,
        )
    if output_format == OutputFormat.MARKDOWN:
        return _plain_output(markdown.format_versions(package, versions))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_versions(package, versions))
    return tables.render_versions(package, versions, color=color)


def render_artifacts(
    output_format: OutputFormat,
    release: ReleaseArtifacts,
    *,
    arguments: dict[str, object],
    color: bool,
    detailed: bool,
    retrieved_at: str,
    freshness: Freshness | None = None,
    publishers: bool = False,
) -> str:
    """Render a release's artifacts in the selected format.

    Returns:
        The rendered output.
    """
    if output_format == OutputFormat.JSON:
        return json.format_artifacts(
            release,
            arguments=arguments,
            retrieved_at=retrieved_at,
            freshness=freshness,
            publishers=publishers,
        )
    if output_format == OutputFormat.MARKDOWN:
        return _plain_output(markdown.format_artifacts(release, detailed=detailed))
    if output_format == OutputFormat.TEXT:
        return _plain_output(text.format_artifacts(release, detailed=detailed))
    return tables.render_artifacts(release, color=color, detailed=detailed)
