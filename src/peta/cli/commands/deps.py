"""The ``peta deps`` command."""

from __future__ import annotations

import typer

from peta.core.deptree import build_tree, find_why
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.output.json import format_dep_tree, format_why
from peta.output.tables import render_dep_tree, render_why

__all__ = ["deps"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _print_why(
    package: str,
    target: str,
    paths: list[list[str]],
    *,
    use_json: bool,
    color: bool,
    depth: int,
) -> None:
    if not paths:
        msg = (
            f"'{target}' was not found in the dependency tree of "
            f"'{package}' (depth {depth})."
        )
        typer.echo(msg, err=True)
        raise typer.Exit(code=1)
    typer.echo(
        format_why(target, paths)
        if use_json
        else render_why(target, paths, color=color)
    )


def deps(
    package: str,
    *,
    use_json: bool = False,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    why: str | None = None,
    depth: int = 10,
) -> None:
    """Show a package's recursive dependency tree, or ``--why`` a target is pulled in.

    Raises:
        Exit: With code 1 if the package (or, with ``--why``, the target) is
            not found, or code 2 on network failure.
    """
    try:
        tree = build_tree(package, local=local, remote=remote, max_depth=depth)
    except _NOT_FOUND:
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None

    if why is not None:
        _print_why(
            package,
            why,
            find_why(tree, why),
            use_json=use_json,
            color=color,
            depth=depth,
        )
        return
    typer.echo(
        format_dep_tree(tree) if use_json else render_dep_tree(tree, color=color)
    )
