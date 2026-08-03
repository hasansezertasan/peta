"""Typer application and command registration."""

from __future__ import annotations

import sys

import typer

from peta import __version__
from peta.cli.commands import deps as deps_mod
from peta.cli.commands import files as files_mod
from peta.cli.commands import info as info_mod
from peta.cli.commands import versions as versions_mod

_SUBCOMMANDS = {"info", "deps", "files", "versions", "--help", "-h", "--version", "-V"}

app = typer.Typer(
    name="peta",
    help="Human-friendly Python package metadata viewer.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"peta {__version__}")
        raise typer.Exit


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(  # noqa: ARG001
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Human-friendly Python package metadata viewer."""


@app.command()
def info(
    package: str = typer.Argument(..., help="Package name (optionally name==version)."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    local: bool = typer.Option(False, "--local", "-l", help="Force local lookup."),
    remote: bool = typer.Option(False, "--remote", "-r", help="Force PyPI lookup."),
) -> None:
    """Show detailed package metadata."""
    info_mod.info(package, use_json=use_json, local=local, remote=remote)


@app.command()
def deps(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    local: bool = typer.Option(False, "--local", "-l", help="Force local lookup."),
    remote: bool = typer.Option(False, "--remote", "-r", help="Force PyPI lookup."),
) -> None:
    """Show a package's declared dependencies."""
    deps_mod.deps(package, use_json=use_json, local=local, remote=remote)


@app.command()
def files(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List files installed by a local package."""
    files_mod.files(package, use_json=use_json)


@app.command()
def versions(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    limit: int = typer.Option(20, "--limit", "-n", help="Max versions to show."),
) -> None:
    """Show published versions of a package from PyPI."""
    versions_mod.versions(package, use_json=use_json, limit=limit)


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
