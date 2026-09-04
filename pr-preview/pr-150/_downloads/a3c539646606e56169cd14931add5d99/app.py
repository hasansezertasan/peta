"""Typer application and command registration."""

from __future__ import annotations

import sys
from importlib.metadata import Distribution, PackageNotFoundError
from typing import Annotated, cast

import typer

from peta.__metadata__ import PROJECT_NAME
from peta.cli.commands import (
    compare as compare_mod,
    deps as deps_mod,
    files as files_mod,
    info as info_mod,
    versions as versions_mod,
)
from peta.cli.output.console import resolve_color
from peta.cli.output.errors import StructuredErrorGroup
from peta.cli.output.selection import OutputFormat
from peta.cli.state import CliState

__all__ = ["compare", "deps", "files", "info", "main", "run", "versions"]


_SUBCOMMANDS = {
    "info",
    "deps",
    "files",
    "versions",
    "compare",
    "--help",
    "-h",
    "--version",
    "-V",
}

_FORMAT_HELP = "Output format: rich, text, json, or markdown."

app = typer.Typer(
    name="peta",
    cls=StructuredErrorGroup,
    help="Human-friendly Python package metadata viewer.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if not value:
        return
    try:
        distribution = Distribution.from_name(PROJECT_NAME)
    except PackageNotFoundError as exc:
        typer.echo("Error: peta package metadata not found.", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"peta {distribution.version}")
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
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help=_FORMAT_HELP)
    ] = OutputFormat.RICH,
    local: Annotated[
        bool, typer.Option("--local", "-l", help="Force local lookup.")
    ] = False,
    remote: Annotated[
        bool, typer.Option("--remote", "-r", help="Force PyPI lookup.")
    ] = False,
    no_osv: Annotated[
        bool, typer.Option("--no-osv", help="Skip the OSV vulnerability lookup.")
    ] = False,
    no_stats: Annotated[
        bool, typer.Option("--no-stats", help="Skip download/dependent count lookups.")
    ] = False,
) -> None:
    """Show detailed package metadata."""
    info_mod.info(
        package,
        use_json=use_json,
        output_format=output_format,
        local=local,
        remote=remote,
        color=_color_from_ctx(ctx),
        no_osv=no_osv,
        no_stats=no_stats,
    )


@app.command()
def compare(
    ctx: typer.Context,
    a: Annotated[str, typer.Argument(help="First package name.")],
    b: Annotated[str, typer.Argument(help="Second package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help=_FORMAT_HELP)
    ] = OutputFormat.RICH,
    local: Annotated[
        bool, typer.Option("--local", "-l", help="Force local lookup.")
    ] = False,
    remote: Annotated[
        bool, typer.Option("--remote", "-r", help="Force PyPI lookup.")
    ] = False,
    no_osv: Annotated[
        bool, typer.Option("--no-osv", help="Skip the OSV vulnerability lookup.")
    ] = False,
    no_stats: Annotated[
        bool, typer.Option("--no-stats", help="Skip download/dependent count lookups.")
    ] = False,
) -> None:
    """Compare two packages' metadata side by side."""
    compare_mod.compare(
        a,
        b,
        use_json=use_json,
        output_format=output_format,
        local=local,
        remote=remote,
        color=_color_from_ctx(ctx),
        no_osv=no_osv,
        no_stats=no_stats,
    )


@app.command()
def deps(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help=_FORMAT_HELP)
    ] = OutputFormat.RICH,
    local: Annotated[
        bool, typer.Option("--local", "-l", help="Force local lookup.")
    ] = False,
    remote: Annotated[
        bool, typer.Option("--remote", "-r", help="Force PyPI lookup.")
    ] = False,
    why: Annotated[
        str | None, typer.Option("--why", help="Show why TARGET is a dependency.")
    ] = None,
    depth: Annotated[
        int, typer.Option("--depth", min=1, help="Max recursion depth.")
    ] = 10,
) -> None:
    """Show a package's recursive dependency tree."""
    deps_mod.deps(
        package,
        use_json=use_json,
        output_format=output_format,
        local=local,
        remote=remote,
        color=_color_from_ctx(ctx),
        why=why,
        depth=depth,
    )


@app.command()
def files(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help=_FORMAT_HELP)
    ] = OutputFormat.RICH,
) -> None:
    """List files installed by a local package."""
    files_mod.files(
        package,
        use_json=use_json,
        output_format=output_format,
        color=_color_from_ctx(ctx),
    )


@app.command()
def versions(
    ctx: typer.Context,
    package: Annotated[str, typer.Argument(help="Package name.")],
    use_json: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help=_FORMAT_HELP)
    ] = OutputFormat.RICH,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, help="Max versions to show.")
    ] = 20,
) -> None:
    """Show published versions of a package from PyPI."""
    versions_mod.versions(
        package,
        use_json=use_json,
        output_format=output_format,
        limit=limit,
        color=_color_from_ctx(ctx),
    )


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
