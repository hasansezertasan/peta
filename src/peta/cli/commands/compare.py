"""The ``peta compare`` command."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

import typer

from peta.cli.output.render import render_compare, render_target
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core import http
from peta.core.artifacts import Target, get_release, parse_target
from peta.core.concurrency import gather
from peta.core.diff import ReleaseEvidence, diff_packages
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


def _release_evidence(pkg: PackageInfo, target: Target) -> ReleaseEvidence:
    """Fetch one side's artifact listing from PyPI, never failing the command.

    The listing is optional evidence: the metadata comparison stands without
    it, so a failed or missing listing is recorded as the reason its groups
    are unknown rather than turned into an error.

    Returns:
        The listing, or why there is none.
    """
    try:
        release, retrieval = get_release(pkg.name, pkg.version, target=target)
    except (NetworkError, http.OfflineError) as exc:
        return ReleaseEvidence(reason=f"{pkg.name} {pkg.version}: {exc}")
    if release is None:
        return ReleaseEvidence(
            reason=f"{pkg.name} {pkg.version} is not published on PyPI"
        )
    return ReleaseEvidence(release=release, retrieval=retrieval)


def _artifact_target(target: LocalTarget | None) -> Target:
    """Judge wheel compatibility against the Python the comparison is about.

    With ``--python`` that is the named interpreter's version, not the one
    running peta; without it, the two are the same.

    Returns:
        The compatibility target.
    """
    if target is None:
        return Target()
    return parse_target(target.marker_environment.get("python_version"))


def _fetch_releases(
    a_pkg: PackageInfo, b_pkg: PackageInfo, target: Target
) -> tuple[ReleaseEvidence, ReleaseEvidence]:
    """Fetch both sides' artifact listings at once.

    Returns:
        The two listings, in argument order.
    """
    first, second = gather([
        partial(_release_evidence, a_pkg, target),
        partial(_release_evidence, b_pkg, target),
    ])
    return first, second


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
    changes_only: bool = False,
    artifacts: bool = False,
) -> None:
    """Compare two packages, or two releases of one, and explain what changed."""
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
        "changes_only": changes_only,
        "artifacts": artifacts,
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
    releases = (
        _fetch_releases(a_pkg, b_pkg, _artifact_target(target)) if artifacts else None
    )
    diff = diff_packages(
        a_pkg,
        b_pkg,
        a_release=releases[0] if releases else None,
        b_release=releases[1] if releases else None,
        osv_skipped=no_osv,
    )
    rendered = render_compare(
        selected,
        a_pkg,
        b_pkg,
        arguments=arguments,
        color=color,
        diff=diff,
        releases=releases,
        changes_only=changes_only,
    )
    if target and selected != OutputFormat.JSON:
        rendered = f"{render_target(selected, target)}\n{rendered}"
    typer.echo(rendered)
