"""The ``peta deps`` command."""

from __future__ import annotations

import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.local import get_package as local_get_package
from peta.core.models import PackageInfo
from peta.core.remote import NetworkError
from peta.core.remote import PackageNotFoundError as RemoteNotFound
from peta.core.remote import get_package as remote_get_package
from peta.output.json import format_deps as json_format
from peta.output.tables import render_deps as rich_format


def _resolve(package: str, *, local: bool, remote: bool) -> PackageInfo:
    if remote:
        return remote_get_package(package)
    if local:
        return local_get_package(package)
    try:
        return local_get_package(package)
    except LocalNotFound:
        return remote_get_package(package)


def deps(package: str, *, use_json: bool = False, local: bool = False, remote: bool = False) -> None:
    """Show a package's declared dependencies."""
    try:
        pkg = _resolve(package, local=local, remote=remote)
    except (LocalNotFound, RemoteNotFound):
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
