"""The ``peta info`` command."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import typer

from peta.core import osv, stats
from peta.core.local import (
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.core.remote import (
    NetworkError,
    PackageNotFoundError as RemoteNotFound,
    get_package as remote_get_package,
)
from peta.core.vulns import merge_vulnerabilities
from peta.output.json import format_info as json_format
from peta.output.tables import render_info as rich_format

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["info"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_NOT_FOUND = (LocalNotFound, RemoteNotFound)


def _parse_package_arg(package: str) -> tuple[str, str | None]:
    if "==" in package:
        name, version = package.split("==", 1)
        return name.strip(), version.strip()
    return package, None


def _resolve_versioned(name: str, version: str, *, local: bool) -> PackageInfo:
    if local:
        msg = "--local cannot be combined with a version specifier."
        raise typer.BadParameter(msg)
    return remote_get_package(name, version)


def _resolve(package: str, *, local: bool, remote: bool) -> PackageInfo:
    name, version = _parse_package_arg(package)
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


def _enrich_with_osv(pkg: PackageInfo) -> PackageInfo:
    osv_vulns = osv.get_vulnerabilities(pkg.name, pkg.version)
    return dataclasses.replace(
        pkg, vulnerabilities=merge_vulnerabilities(pkg.vulnerabilities, osv_vulns)
    )


def _enrich_with_stats(pkg: PackageInfo) -> PackageInfo:
    return dataclasses.replace(
        pkg,
        download_count=stats.get_download_count(pkg.name),
        dependent_count=stats.get_dependent_count(
            pkg.name, api_key=stats.libraries_io_api_key()
        ),
    )


def _resolve_and_enrich(
    package: str, *, local: bool, remote: bool, no_osv: bool, no_stats: bool
) -> PackageInfo:
    pkg = _resolve(package, local=local, remote=remote)
    if not no_osv:
        pkg = _enrich_with_osv(pkg)
    if not no_stats:
        pkg = _enrich_with_stats(pkg)
    return pkg


def info(
    package: str,
    *,
    use_json: bool = False,
    local: bool = False,
    remote: bool = False,
    color: bool = False,
    no_osv: bool = False,
    no_stats: bool = False,
) -> None:
    """Show detailed package metadata.

    Raises:
        Exit: With code 1 if the package is not found, or code 2 on network failure.
    """
    try:
        pkg = _resolve_and_enrich(
            package, local=local, remote=remote, no_osv=no_osv, no_stats=no_stats
        )
    except _NOT_FOUND:
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg, color=color))
