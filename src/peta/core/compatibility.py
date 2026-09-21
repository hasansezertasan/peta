"""Shared package compatibility checks."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from packaging.specifiers import InvalidSpecifier, SpecifierSet

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["supports_python"]


def supports_python(
    package: PackageInfo, marker_environment: dict[str, str] | None
) -> bool:
    """Report whether package metadata permits the selected Python target.

    Returns:
        ``False`` for an invalid ``Requires-Python`` value or an incompatible
        target; otherwise ``True``.
    """
    if not package.python_requires:
        return True
    try:
        specifier = SpecifierSet(package.python_requires)
    except InvalidSpecifier:
        return False
    if marker_environment is not None:
        python_version = marker_environment.get("python_full_version", "")
    else:
        version = sys.version_info
        python_version = f"{version.major}.{version.minor}.{version.micro}"
    return bool(specifier.contains(python_version))
