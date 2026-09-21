"""The ``peta files`` command."""

from __future__ import annotations

import typer

from peta.cli.output.render import render_files
from peta.cli.output.selection import OutputFormat, fail, resolve_or_fail
from peta.core.local import (
    LocalTarget,
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.core.output import TARGET_ENVIRONMENT_KEY

__all__ = ["files"]


def files(
    package: str,
    *,
    use_json: bool = False,
    output_format: OutputFormat | None = None,
    color: bool = False,
    python: str | None = None,
    paths: tuple[str, ...] = (),
) -> None:
    """List files installed by a local package."""
    # Recorded before the target is built so a rejected ``--python``/``--path``
    # still appears in the error envelope; see the note in ``info``.
    arguments: dict[str, object] = {
        "package": package,
        "python": python,
        "paths": list(paths),
    }
    selected = resolve_or_fail("files", arguments, output_format, use_json=use_json)
    try:
        # ``python is not None`` rather than a truthiness test: ``--python ""``
        # must be rejected as an unusable interpreter, not silently fall back
        # to the environment running peta.
        target = (
            LocalTarget.create(python, paths) if python is not None or paths else None
        )
        if target:
            arguments[TARGET_ENVIRONMENT_KEY] = target.output_environment()
        pkg = (
            local_get_package(package, target=target)
            if target
            else local_get_package(package)
        )
    except LocalNotFound:
        fail(
            "files",
            arguments=arguments,
            code="package_not_found",
            message=f"Package '{package}' not found locally.",
            output_format=selected,
            exit_code=1,
            source="local",
        )
    except ValueError as exc:
        fail(
            "files",
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )
    rendered = render_files(selected, pkg, arguments=arguments, color=color)
    if target and selected != OutputFormat.JSON:
        rendered = f"{target.describe()}\n{rendered}"
    typer.echo(rendered)
