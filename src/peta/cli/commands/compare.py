"""The ``peta compare`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_compare
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.enrich import enrich
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import not_found_source, resolve_package

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
    output_format: OutputFormat | None = None,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    no_osv: bool = False,
    no_stats: bool = False,
) -> None:
    """Compare two packages' metadata side by side."""
    arguments: dict[str, object] = {
        "a": a,
        "b": b,
        "local": local,
        "remote": remote,
        "no_osv": no_osv,
        "no_stats": no_stats,
    }
    selected = resolve_or_fail("compare", arguments, output_format, use_json=use_json)
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
        fail(
            "compare",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{target}' not found.",
            output_format=selected,
            exit_code=1,
            source=not_found_source(exc),
        )
    except typer.BadParameter as exc:
        fail(
            "compare",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    except NetworkError as exc:
        fail(
            "compare",
            arguments=arguments,
            code="network_error",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    rendered = render_compare(selected, a_pkg, b_pkg, arguments=arguments, color=color)
    typer.echo(rendered)
