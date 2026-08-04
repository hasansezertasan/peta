"""The ``peta compare`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.json import format_compare as json_format
from peta.cli.output.tables import render_compare as rich_format
from peta.core.enrich import enrich
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import resolve_package

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["compare"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _resolve_and_enrich(
    package: str, *, local: bool, remote: bool, no_osv: bool, no_stats: bool
) -> PackageInfo:
    pkg = resolve_package(package, local=local, remote=remote)
    return enrich(pkg, no_osv=no_osv, no_stats=no_stats)


def compare(
    a: str,
    b: str,
    *,
    use_json: bool = False,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    no_osv: bool = False,
    no_stats: bool = False,
) -> None:
    """Compare two packages' metadata side by side.

    Raises:
        Exit: With code 1 if either package is not found, or code 2 on network
            failure.
    """
    try:
        a_pkg = _resolve_and_enrich(
            a, local=local, remote=remote, no_osv=no_osv, no_stats=no_stats
        )
        b_pkg = _resolve_and_enrich(
            b, local=local, remote=remote, no_osv=no_osv, no_stats=no_stats
        )
    except _NOT_FOUND as exc:
        version = getattr(exc, "version", None)
        target = f"{exc.name}=={version}" if version else exc.name
        typer.echo(f"Package '{target}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(
        json_format(a_pkg, b_pkg)
        if use_json
        else rich_format(a_pkg, b_pkg, color=color)
    )
