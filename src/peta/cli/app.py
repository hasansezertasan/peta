"""Typer application and command registration."""

from __future__ import annotations

import sys
from typing import Annotated, cast

import typer

from peta import __version__
from peta.cli.commands import (
    deps as deps_mod,
    files as files_mod,
    info as info_mod,
    versions as versions_mod,
)
from peta.cli.state import CliState
from peta.output.console import resolve_color

__all__ = ["deps", "files", "info", "main", "run", "versions"]


_SUBCOMMANDS = {"info", "deps", "files", "versions", "--help", "-h", "--version", "-V"}

app = typer.Typer(
    name="peta",
    help="Human-friendly Python package metadata viewer.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"peta {__version__}")
        raise typer.Exit


def _color_from_ctx(ctx: typer.Context) -> bool:
    """Read the resolved color setting stashed on the root context.

    Returns:
        The resolved color flag, or ``False`` if unavailable (e.g. the root
        callback did not run, as can happen when invoking a command object
        directly in tests).
    """
    obj = cast("object", ctx.obj)
    return obj.color if isinstance(obj, CliState) else False


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable colored output.")
    ] = False,
) -> None:
    """Human-friendly Python package metadata viewer."""
    ctx.obj = CliState(color=resolve_color(no_color=no_color))


@app.command()
def info(
    ctx: typer.Context,
    package: Annotated[
        str, typer.Argument(help="Package name (optionally name==version).")
    ],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    local: Annotated[
        bool, typer.Option("--local", "-l", help="Force local lookup.")
    ] = False,
    remote: Annotated[
        bool, typer.Option("--remote", "-r", help="Force PyPI lookup.")
    ] = False,
) -> None:
    """Show detailed package metadata."""
    info_mod.info(
        package,
        use_json=use_json,
        local=local,
        remote=remote,
        color=_color_from_ctx(ctx),
    )


@app.command()
def deps(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    local: Annotated[
        bool, typer.Option("--local", "-l", help="Force local lookup.")
    ] = False,
    remote: Annotated[
        bool, typer.Option("--remote", "-r", help="Force PyPI lookup.")
    ] = False,
) -> None:
    """Show a package's declared dependencies."""
    deps_mod.deps(
        package,
        use_json=use_json,
        local=local,
        remote=remote,
        color=_color_from_ctx(ctx),
    )


@app.command()
def files(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
) -> None:
    """List files installed by a local package."""
    files_mod.files(package, use_json=use_json, color=_color_from_ctx(ctx))


@app.command()
def versions(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, help="Max versions to show.")
    ] = 20,
) -> None:
    """Show published versions of a package from PyPI."""
    versions_mod.versions(
        package, use_json=use_json, limit=limit, color=_color_from_ctx(ctx)
    )


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
