"""The ``peta files`` command."""

from __future__ import annotations

import typer

from peta.core.local import (
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.output.json import format_files as json_format
from peta.output.tables import render_files as rich_format

__all__ = ["files"]


def files(package: str, *, use_json: bool = False, color: bool = False) -> None:
    """List files installed by a local package.

    Raises:
        Exit: With code 1 if the package is not installed locally.
    """
    try:
        pkg = local_get_package(package)
    except LocalNotFound:
        typer.echo(f"Package '{package}' not found locally.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg, color=color))
