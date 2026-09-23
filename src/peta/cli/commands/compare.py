"""The ``peta compare`` command."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_compare, render_target
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core import http
from peta.core.concurrency import gather
from peta.core.enrich import enrich
from peta.core.local import LocalTarget, PackageNotFoundError as LocalNotFound
from peta.core.output import TARGET_ENVIRONMENT_KEY
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import not_found_source, resolve_package

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["compare"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _resolve_and_enrich(
    package: str,
    *,
    local: bool,
    remote: bool,
    no_osv: bool,
    no_stats: bool,
    target: LocalTarget | None,
) -> PackageInfo:
    pkg = resolve_package(package, local=local, remote=remote, target=target)
    return enrich(pkg, no_osv=no_osv, no_stats=no_stats)


def compare(  # ruff: ignore[complex-structure, too-many-arguments]
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
    python: str | None = None,
    paths: tuple[str, ...] = (),
) -> None:
    """Compare two packages' metadata side by side."""
    # Recorded before the target is built so a rejected ``--python``/``--path``
    # still appears in the error envelope; see the note in ``info``.
    arguments: dict[str, object] = {
        "a": a,
        "b": b,
        "local": local,
        "remote": remote,
        "no_osv": no_osv,
        "no_stats": no_stats,
        "python": python,
        "paths": list(paths),
    }
    selected = resolve_or_fail("compare", arguments, output_format, use_json=use_json)
    try:
        # Built before ``gather`` so an unusable target fails once, here,
        # rather than racing as the same error out of two worker threads.
        # ``python is not None`` rather than a truthiness test: ``--python ""``
        # must be rejected as an unusable interpreter, not silently fall back
        # to the environment running peta.
        target = (
            LocalTarget.create(python, paths) if python is not None or paths else None
        )
        if target:
            arguments[TARGET_ENVIRONMENT_KEY] = target.output_environment()
        # Both sides at once: they are unrelated lookups, and waiting for the
        # first before starting the second doubled the command's latency.
        # ``gather`` returns them in the order asked for, so which package is
        # rendered on which side never depends on which answered first.
        a_pkg, b_pkg = gather([
            partial(
                _resolve_and_enrich,
                a,
                local=local,
                remote=remote,
                no_osv=no_osv,
                no_stats=no_stats,
                target=target,
            ),
            partial(
                _resolve_and_enrich,
                b,
                local=local,
                remote=remote,
                no_osv=no_osv,
                no_stats=no_stats,
                target=target,
            ),
        ])
    except _NOT_FOUND as exc:
        version = getattr(exc, "version", None)
        # Named ``missing`` rather than ``target``: that name now holds the
        # LocalTarget for this invocation.
        missing = f"{exc.name}=={version}" if version else exc.name
        fail(
            "compare",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{missing}' not found.",
            output_format=selected,
            exit_code=1,
            source=not_found_source(exc),
        )
    except (typer.BadParameter, ValueError) as exc:
        fail(
            "compare",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    except http.OfflineError as exc:
        fail(
            "compare",
            arguments=arguments,
            code="offline_unavailable",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
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
    if target and selected != OutputFormat.JSON:
        rendered = f"{render_target(selected, target)}\n{rendered}"
    typer.echo(rendered)
