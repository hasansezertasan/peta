"""The ``peta deps`` command."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.core.local import (
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.core.remote import (
    NetworkError,
    PackageNotFoundError as RemoteNotFound,
    get_package as remote_get_package,
)
from peta.output.json import format_deps as json_format
from peta.output.tables import render_deps as rich_format

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _resolve(package: str, *, local: bool, remote: bool) -> PackageInfo:
    if remote:
        return remote_get_package(package)
    if local:
        return local_get_package(package)
    try:
        return local_get_package(package)
    except LocalNotFound:
        return remote_get_package(package)


def deps(
    package: str, *, use_json: bool = False, local: bool = False, remote: bool = False
) -> None:
    """Show a package's declared dependencies.

    Raises:
        Exit: With code 1 if the package is not found, or code 2 on network failure.
    """
    try:
        pkg = _resolve(package, local=local, remote=remote)
    except _NOT_FOUND:
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
