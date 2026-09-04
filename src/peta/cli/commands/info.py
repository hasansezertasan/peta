"""The ``peta info`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_info
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.enrich import enrich
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import not_found_source, resolve_package

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
    output_format: OutputFormat | None = None,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    no_osv: bool = False,
    no_stats: bool = False,
) -> None:
    """Show detailed package metadata."""
    arguments: dict[str, object] = {
        "package": package,
        "local": local,
        "remote": remote,
        "no_osv": no_osv,
        "no_stats": no_stats,
    }
    selected = resolve_or_fail("info", arguments, output_format, use_json=use_json)
    try:
        pkg = _resolve_and_enrich(
            package, local=local, remote=remote, no_osv=no_osv, no_stats=no_stats
        )
    except _NOT_FOUND as exc:
        fail(
            "info",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found.",
            output_format=selected,
            exit_code=1,
            source=not_found_source(exc),
        )
    except typer.BadParameter as exc:
        fail(
            "info",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    except NetworkError as exc:
        fail(
            "info",
            arguments=arguments,
            code="network_error",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    rendered = render_info(selected, pkg, arguments=arguments, color=color)
    typer.echo(rendered)
