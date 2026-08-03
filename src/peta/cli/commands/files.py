"""The ``peta files`` command."""

from __future__ import annotations

import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.local import get_package as local_get_package
from peta.output.json import format_files as json_format
from peta.output.tables import render_files as rich_format


def files(package: str, *, use_json: bool = False) -> None:
    """List files installed by a local package."""
    try:
        pkg = local_get_package(package)
    except LocalNotFound:
        typer.echo(f"Package '{package}' not found locally.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
