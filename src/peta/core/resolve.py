"""Shared package-resolution logic for the ``info`` and ``compare`` commands."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import typer
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from peta.core.local import (
    LocalTarget,
    PackageNotFoundError as LocalNotFound,
    get_package as local_get_package,
)
from peta.core.remote import (
    get_package as remote_get_package,
    get_package_matching as remote_get_package_matching,
)

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["not_found_source", "parse_package_arg", "resolve_package"]


def not_found_source(exc: BaseException) -> str:
    """Name the provider that reported a package as missing.

    Returns:
        ``"local"`` for the installed environment, otherwise ``"pypi"``.
    """
    return "local" if isinstance(exc, LocalNotFound) else "pypi"


def parse_package_arg(package: str) -> tuple[str, str | None]:
    """Split a ``name`` or ``name==version`` argument.

    Returns:
        A ``(name, version)`` tuple; ``version`` is ``None`` when unspecified.

    Raises:
        typer.BadParameter: If the package name is empty, or the argument
            contains ``==`` but the version text after it is empty.
    """
    if "==" in package:
        name, version = package.split("==", 1)
        name, version = name.strip(), version.strip()
        if not version:
            msg = f"Missing version after '==' in {package!r}."
            raise typer.BadParameter(msg)
    else:
        name, version = package.strip(), None
    if not name:
        msg = f"Missing package name in {package!r}."
        raise typer.BadParameter(msg)
    return name, version


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


def _remote_package(
    name: str, specifier: SpecifierSet, target: LocalTarget | None
) -> PackageInfo:
    """Get the newest remote release that meets the dependency requirement.

    Returns:
        The selected remote package metadata.
    """
    if not specifier and target is None:
        package = remote_get_package(name)
        if _supports_target(package, None):
            return package
    return remote_get_package_matching(
        name, specifier, target.marker_environment if target else None
    )


def _supports_target(pkg: PackageInfo, target: LocalTarget | None) -> bool:
    if not pkg.python_requires:
        return True
    try:
        spec = SpecifierSet(pkg.python_requires)
    except InvalidSpecifier:
        return False
    if target is None:
        version = sys.version_info
        python_version = f"{version.major}.{version.minor}.{version.micro}"
    else:
        python_version = target.marker_environment.get("python_full_version", "")
    return bool(spec.contains(python_version))


def _resolve_default(
    name: str, requirement: SpecifierSet, target: LocalTarget | None
) -> PackageInfo:
    try:
        local_pkg = (
            local_get_package(name, target=target)
            if target
            else local_get_package(name)
        )
    except LocalNotFound:
        if target is not None and (target.interpreter is not None or target.paths):
            raise
        return _remote_package(name, requirement, target)

    allows_prereleases = not requirement or requirement.prereleases is True
    if requirement.contains(
        local_pkg.version, prereleases=allows_prereleases
    ) and _supports_target(local_pkg, target):
        return local_pkg
    return _remote_package(name, requirement, target)


def _reject_remote_metadata_target(target: LocalTarget | None) -> None:
    if target is not None and (target.interpreter is not None or target.paths):
        msg = "--remote cannot be combined with --python or --path."
        raise typer.BadParameter(msg)


def resolve_package(
    package: str,
    *,
    local: bool,
    remote: bool,
    target: LocalTarget | None = None,
    specifier: SpecifierSet | None = None,
) -> PackageInfo:
    """Resolve a package argument to its metadata.

    Checks the local environment first and falls back to PyPI, unless
    ``--local``/``--remote`` force a source or a ``name==version`` specifier
    is given (which always queries PyPI and rejects ``--local``).

    Returns:
        The resolved package metadata.

    Raises:
        typer.BadParameter: If source-selection options conflict.
    """
    name, version = parse_package_arg(package)
    requirement = specifier or SpecifierSet()
    if version:
        if target is not None and (target.interpreter is not None or target.paths):
            msg = "--python and --path cannot be combined with a version specifier."
            raise typer.BadParameter(msg)
        return _resolve_versioned(name, version, local=local)
    if remote:
        _reject_remote_metadata_target(target)
        return _remote_package(name, requirement, target)
    if local:
        return (
            local_get_package(name, target=target)
            if target
            else local_get_package(name)
        )
    return _resolve_default(name, requirement, target)
