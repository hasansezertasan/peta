"""The ``peta deps`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_dep_tree, render_target, render_why
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core import http
from peta.core.deptree import build_tree, find_why
from peta.core.local import LocalTarget, PackageNotFoundError as LocalNotFound
from peta.core.output import TARGET_ENVIRONMENT_KEY
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import not_found_source

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


def _build_or_fail(
    package: str,
    *,
    local: bool,
    remote: bool,
    depth: int,
    selected: OutputFormat,
    arguments: dict[str, object],
    target: LocalTarget | None,
    extras: tuple[str, ...],
) -> DependencyNode:
    """Resolve the tree, or render the failure and exit.

    Extracted from :func:`deps` so the command body stays within the
    project's complexity limit as error kinds accumulate.

    Returns:
        The resolved dependency tree.
    """
    try:
        return build_tree(
            package,
            local=local,
            remote=remote,
            target=target,
            max_depth=depth,
            extras=extras,
        )
    except _NOT_FOUND as exc:
        fail(
            "deps",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found.",
            output_format=selected,
            exit_code=1,
            source=not_found_source(exc),
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
    except http.OfflineError as exc:
        fail(
            "deps",
            arguments=arguments,
            code="offline_unavailable",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
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


def deps(  # ruff: ignore[complex-structure, too-many-arguments]
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat | None = None,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    why: str | None = None,
    depth: int = 10,
    python: str | None = None,
    python_version: str | None = None,
    platform: str | None = None,
    extras: tuple[str, ...] = (),
    paths: tuple[str, ...] = (),
) -> None:
    """Show a package's recursive dependency tree, or why a target is pulled in."""
    # Recorded before the target is built so a rejected ``--python``/``--path``
    # still appears in the error envelope; see the note in ``info``.
    arguments: dict[str, object] = {
        "package": package,
        "local": local,
        "remote": remote,
        "why": why,
        "depth": depth,
        "python": python,
        "python_version": python_version,
        "platform": platform,
        "extras": list(extras),
        "paths": list(paths),
    }
    try:
        # ``python is not None`` rather than a truthiness test: ``--python ""``
        # must be rejected as an unusable interpreter, not silently fall back
        # to the environment running peta.
        target = (
            LocalTarget.create(python, paths, python_version, platform)
            if python is not None
            or paths
            or python_version is not None
            or platform is not None
            else None
        )
    except ValueError as exc:
        fail(
            "deps",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=resolve_or_fail(
                "deps", arguments, output_format, use_json=use_json
            ),
            exit_code=2,
        )
    if target:
        arguments[TARGET_ENVIRONMENT_KEY] = target.output_environment()
    selected = resolve_or_fail("deps", arguments, output_format, use_json=use_json)
    tree = _build_or_fail(
        package,
        local=local,
        remote=remote,
        depth=depth,
        selected=selected,
        arguments=arguments,
        target=target,
        extras=extras,
    )

    if why is not None:
        if target and selected != OutputFormat.JSON:
            typer.echo(render_target(selected, target))
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
    rendered_target = (
        render_target(selected, target)
        if target and selected != OutputFormat.JSON
        else ""
    )
    if rendered_target:
        typer.echo(rendered_target)
    _print_tree(tree, output_format=selected, arguments=arguments, color=color)
