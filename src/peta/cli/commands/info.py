"""The ``peta info`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.json import format_info as json_format
from peta.cli.output.tables import render_info as rich_format
from peta.core.enrich import enrich
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import resolve_package

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["info"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _resolve_and_enrich(
    package: str, *, local: bool, remote: bool, no_osv: bool, no_stats: bool
) -> PackageInfo:
    pkg = resolve_package(package, local=local, remote=remote)
    return enrich(pkg, no_osv=no_osv, no_stats=no_stats)


def info(
    package: str,
    *,
    use_json: bool = False,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    no_osv: bool = False,
    no_stats: bool = False,
) -> None:
    """Show detailed package metadata.

    Raises:
        Exit: With code 1 if the package is not found, or code 2 on network failure.
    """
    try:
        pkg = _resolve_and_enrich(
            package, local=local, remote=remote, no_osv=no_osv, no_stats=no_stats
        )
    except _NOT_FOUND:
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg, color=color))
