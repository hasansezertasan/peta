"""Shared package-resolution logic for the ``info`` and ``compare`` commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from peta.core.local import (
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.core.remote import get_package as remote_get_package

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["parse_package_arg", "resolve_package"]


def parse_package_arg(package: str) -> tuple[str, str | None]:
    """Split a ``name`` or ``name==version`` argument.

    Returns:
        A ``(name, version)`` tuple; ``version`` is ``None`` when unspecified.
    """
    if "==" in package:
        name, version = package.split("==", 1)
        return name.strip(), version.strip()
    return package, None


def _resolve_versioned(name: str, version: str, *, local: bool) -> PackageInfo:
    """Resolve a ``name==version`` specifier; always queries PyPI.

    Returns:
        The resolved package metadata.

    Raises:
        typer.BadParameter: If ``--local`` is combined with a version
            specifier.
    """
    if local:
        msg = "--local cannot be combined with a version specifier."
        raise typer.BadParameter(msg)
    return remote_get_package(name, version)


def resolve_package(package: str, *, local: bool, remote: bool) -> PackageInfo:
    """Resolve a package argument to its metadata.

    Checks the local environment first and falls back to PyPI, unless
    ``--local``/``--remote`` force a source or a ``name==version`` specifier
    is given (which always queries PyPI and rejects ``--local``).

    Returns:
        The resolved package metadata.
    """
    name, version = parse_package_arg(package)
    if version:
        return _resolve_versioned(name, version, local=local)
    if remote:
        return remote_get_package(name)
    if local:
        return local_get_package(name)
    try:
        return local_get_package(name)
    except LocalNotFound:
        return remote_get_package(name)
