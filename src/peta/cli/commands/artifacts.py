"""The ``peta artifacts`` command."""

from __future__ import annotations

import typer

from peta.cli.output.render import render_artifacts
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core import http
from peta.core.artifacts import Target, get_release, parse_target
from peta.core.remote import NetworkError
from peta.core.resolve import parse_package_arg

__all__ = ["artifacts"]


def _target_or_fail(
    python: str | None, arguments: dict[str, object], selected: OutputFormat
) -> Target:
    """Resolve the ``--python`` option, failing the command if it is unusable.

    Returns:
        The evaluated target.
    """
    try:
        return parse_target(python)
    except ValueError as exc:
        fail(
            "artifacts",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )


def artifacts(
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat | None = None,
    python: str | None = None,
    detailed: bool = False,
    provenance: bool = False,
    color: bool = False,
) -> None:
    """Show a release's distribution files, compatibility, and provenance."""
    arguments: dict[str, object] = {
        "package": package,
        "python": python,
        "files": detailed,
        "provenance": provenance,
    }
    selected = resolve_or_fail("artifacts", arguments, output_format, use_json=use_json)
    target = _target_or_fail(python, arguments, selected)
    try:
        name, version = parse_package_arg(package)
        release, retrieval = get_release(
            name, version, target=target, publishers=provenance
        )
    except typer.BadParameter as exc:
        fail(
            "artifacts",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    except http.OfflineError as exc:
        fail(
            "artifacts",
            arguments=arguments,
            code="offline_unavailable",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    except NetworkError as exc:
        fail(
            "artifacts",
            arguments=arguments,
            code="network_error",
            message=str(exc),
            output_format=selected,
            exit_code=2,
            source="pypi",
        )
    if release is None:
        fail(
            "artifacts",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found on PyPI.",
            output_format=selected,
            exit_code=1,
            source="pypi",
        )
    rendered = render_artifacts(
        selected,
        release,
        arguments=arguments,
        color=color,
        detailed=detailed,
        retrieved_at=retrieval.retrieved_at,
        freshness=retrieval.freshness,
        publishers=provenance,
    )
    typer.echo(rendered)
