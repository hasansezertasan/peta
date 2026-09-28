"""The ``peta origin`` command."""

from __future__ import annotations

import typer

from peta.cli.output.render import render_origin, render_target
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.installation import inspect_installation
from peta.core.local import InvalidTargetError, LocalTarget, PackageNotFoundError
from peta.core.output import TARGET_ENVIRONMENT_KEY

__all__ = ["origin"]


def origin(
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat | None = None,
    color: bool = False,
    python: str | None = None,
    paths: tuple[str, ...] = (),
    verify: bool = False,
) -> None:
    """Show how a local package was installed and whether its files match."""
    # Recorded before the target is built so a rejected ``--python``/``--path``
    # still appears in the error envelope; see the note in ``info``.
    arguments: dict[str, object] = {
        "package": package,
        "python": python,
        "paths": list(paths),
        "verify": verify,
    }
    selected = resolve_or_fail("origin", arguments, output_format, use_json=use_json)
    try:
        # ``python is not None`` rather than a truthiness test: ``--python ""``
        # must be rejected as an unusable interpreter, not silently fall back
        # to the environment running peta.
        target = (
            LocalTarget.create(python, paths) if python is not None or paths else None
        )
        if target:
            arguments[TARGET_ENVIRONMENT_KEY] = target.output_environment()
        installation = inspect_installation(package, target=target, verify=verify)
    except PackageNotFoundError:
        fail(
            "origin",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found locally.",
            output_format=selected,
            exit_code=1,
            source="local",
        )
    # Only the target's own error: anything else raised while inspecting is a
    # bug, and reporting it as a bad argument would send the user after the
    # wrong cause.
    except InvalidTargetError as exc:
        fail(
            "origin",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    rendered = render_origin(selected, installation, arguments=arguments, color=color)
    if target and selected != OutputFormat.JSON:
        rendered = f"{render_target(selected, target)}\n{rendered}"
    typer.echo(rendered)
