"""The ``peta deps`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_dep_tree, render_why
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.deptree import build_tree, find_why
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound

if TYPE_CHECKING:
    from peta.core.models import DependencyNode

__all__ = ["deps"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _print_why(
    package: str,
    target: str,
    paths: list[list[str]],
    tree: DependencyNode,
    *,
    output_format: OutputFormat,
    color: bool,
    depth: int,
    arguments: dict[str, object],
) -> None:
    if not paths:
        msg = (
            f"'{target}' was not found in the dependency tree of "
            f"'{package}' (depth {depth})."
        )
        fail(
            "deps",
            arguments=arguments,
            code="dependency_not_found",
            message=msg,
            output_format=output_format,
            exit_code=1,
        )
    rendered = render_why(
        output_format, target, paths, tree, arguments=arguments, color=color
    )
    typer.echo(rendered)


def _print_tree(
    tree: DependencyNode,
    *,
    output_format: OutputFormat,
    arguments: dict[str, object],
    color: bool,
) -> None:
    rendered = render_dep_tree(output_format, tree, arguments=arguments, color=color)
    typer.echo(rendered)


def deps(
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat = OutputFormat.RICH,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    why: str | None = None,
    depth: int = 10,
) -> None:
    """Show a package's recursive dependency tree, or why a target is pulled in."""
    arguments: dict[str, object] = {
        "package": package,
        "local": local,
        "remote": remote,
        "why": why,
        "depth": depth,
    }
    selected = resolve_or_fail("deps", arguments, output_format, use_json=use_json)
    try:
        tree = build_tree(package, local=local, remote=remote, max_depth=depth)
    except _NOT_FOUND:
        fail(
            "deps",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found.",
            output_format=selected,
            exit_code=1,
        )
    except typer.BadParameter as exc:
        fail(
            "deps",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    except NetworkError as exc:
        fail(
            "deps",
            arguments=arguments,
            code="network_error",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )

    if why is not None:
        _print_why(
            package,
            why,
            find_why(tree, why),
            tree,
            output_format=selected,
            color=color,
            depth=depth,
            arguments=arguments,
        )
        return
    _print_tree(tree, output_format=selected, arguments=arguments, color=color)
