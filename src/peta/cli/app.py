"""Typer application and command registration."""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from peta import __version__
from peta.cli.commands import (
    deps as deps_mod,
    files as files_mod,
    info as info_mod,
    versions as versions_mod,
)

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


@app.callback(invoke_without_command=True)
def main(
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
) -> None:
    """Human-friendly Python package metadata viewer."""


@app.command()
def info(
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
    info_mod.info(package, use_json=use_json, local=local, remote=remote)


@app.command()
def deps(
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
    deps_mod.deps(package, use_json=use_json, local=local, remote=remote)


@app.command()
def files(
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
) -> None:
    """List files installed by a local package."""
    files_mod.files(package, use_json=use_json)


@app.command()
def versions(
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, help="Max versions to show.")
    ] = 20,
) -> None:
    """Show published versions of a package from PyPI."""
    versions_mod.versions(package, use_json=use_json, limit=limit)


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
