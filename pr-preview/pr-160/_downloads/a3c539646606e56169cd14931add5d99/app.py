"""Typer application and command registration."""

from __future__ import annotations

import sys
from importlib.metadata import Distribution, PackageNotFoundError

# Imported at runtime, not under TYPE_CHECKING: Typer resolves command
# annotations with ``get_type_hints`` to build the parser, so a name used in an
# ``Annotated[...]`` option must exist when the module is imported.
from pathlib import Path  # ruff: ignore[typing-only-standard-library-import]
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
from peta.core import cache

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


def _explicit_format(
    ctx: typer.Context, output_format: OutputFormat
) -> OutputFormat | None:
    """Return the format only when ``--format`` was actually supplied.

    ``None`` marks the untouched default, letting ``--json`` act as the
    documented alias without silently overriding an explicit ``--format``.

    Returns:
        The selected format, or ``None`` when left at its default.
    """
    # Compared by name: Typer vendors its own Click, so its ``ParameterSource``
    # enum is not the one importable from the external ``click`` package.
    source = ctx.get_parameter_source("output_format")
    if source is None or source.name == "DEFAULT":
        return None
    return output_format


def _color_from_ctx(ctx: typer.Context) -> bool:
    """Read the resolved color setting stashed on the root context.

    Returns:
        The resolved color flag, or ``False`` if unavailable (e.g. the root
        callback did not run, as can happen when invoking a command object
        directly in tests).
    """
    obj = cast("object", ctx.obj)
    return obj.color if isinstance(obj, CliState) else False


def _configure_cache(*, offline: bool, refresh: bool, cache_dir: Path | None) -> None:
    """Apply the cache options for this invocation.

    Args:
        offline: Answer only from cache, never from the network.
        refresh: Discard stored entries and fetch again.
        cache_dir: Where to keep the cache; the platform default when ``None``.

    Raises:
        typer.BadParameter: If ``--offline`` and ``--refresh`` are combined,
            which asks peta both to refetch everything and to make no
            requests. Rejected rather than silently resolved, because either
            reading could be what the user meant.
    """
    if offline and refresh:
        msg = "--offline cannot be combined with --refresh."
        raise typer.BadParameter(msg)
    cache.configure(directory=cache_dir, offline=offline, refresh=refresh)


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
    offline: Annotated[
        bool, typer.Option("--offline", help="Use only cached data; make no requests.")
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Ignore cached data and refetch.")
    ] = False,
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Directory for peta's response cache."),
    ] = None,
) -> None:
    """Human-friendly Python package metadata viewer."""
    _configure_cache(offline=offline, refresh=refresh, cache_dir=cache_dir)
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
        output_format=_explicit_format(ctx, output_format),
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
        output_format=_explicit_format(ctx, output_format),
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
        output_format=_explicit_format(ctx, output_format),
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
        output_format=_explicit_format(ctx, output_format),
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
        output_format=_explicit_format(ctx, output_format),
        limit=limit,
        color=_color_from_ctx(ctx),
    )


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
