"""Local package metadata fetcher using importlib.metadata."""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import] # Controlled interpreter invocation below.
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from packaging.markers import default_environment
from packaging.utils import canonicalize_name

from peta.core.models import PackageInfo
from peta.core.output import utc_now

__all__ = ["InvalidTargetError", "LocalTarget", "PackageNotFoundError", "get_package"]


class PackageNotFoundError(Exception):
    """Raised when a package is not installed locally."""

    def __init__(self, name: str) -> None:
        """Store the missing package name."""
        self.name: str = name
        super().__init__(f"Package '{name}' is not installed")


class InvalidTargetError(ValueError):
    """Raised when an explicit local-environment target cannot be used."""


@dataclass(frozen=True)
class LocalTarget:
    """Metadata paths and marker values used for a local inspection."""

    paths: tuple[str, ...] | None
    interpreter: str | None
    marker_environment: dict[str, str]

    @classmethod
    def create(  # ruff: ignore[complex-structure]
        cls, python: str | None = None, paths: tuple[str, ...] = ()
    ) -> LocalTarget:
        """Build a target without implicitly discovering a virtual environment.

        Returns:
            The selected metadata paths and marker environment.

        Raises:
            InvalidTargetError: If a path or interpreter cannot be inspected.
        """
        checked_paths = tuple(str(Path(path).resolve()) for path in paths)
        for path in checked_paths:
            if not Path(path).is_dir():
                msg = f"Invalid metadata path {path!r}: expected an existing directory."
                raise InvalidTargetError(msg)
        if python is None:
            marker_environment = {
                key: str(value) for key, value in default_environment().items()
            }
            return cls(checked_paths or None, None, marker_environment)
        # Do not resolve symlinks: a virtualenv's ``bin/python`` commonly
        # points at its base interpreter, and resolving it loses the venv.
        interpreter = Path(python).absolute()
        if not interpreter.is_file():
            msg = f"Invalid Python interpreter {python!r}: file does not exist."
            raise InvalidTargetError(msg)
        try:
            completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] # Interpreter is the explicit CLI target.
                [str(interpreter), "-c", _TARGET_SCRIPT],
                check=True,
                capture_output=True,
                text=True,
            )
            details = cast("dict[str, object]", json.loads(completed.stdout))
        except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
            msg = f"Invalid Python interpreter {python!r}: could not inspect it."
            raise InvalidTargetError(msg) from exc
        marker = details.get("marker_environment")
        search_paths = details.get("paths")
        if not isinstance(marker, dict) or not isinstance(search_paths, list):
            msg = (
                f"Invalid Python interpreter {python!r}: "
                "returned invalid environment data."
            )
            raise InvalidTargetError(msg)
        raw_paths = cast("list[object]", search_paths)
        raw_marker = cast("dict[object, object]", marker)
        selected_paths = checked_paths or tuple(str(path) for path in raw_paths)
        marker_environment = {str(key): str(value) for key, value in raw_marker.items()}
        return cls(selected_paths, str(interpreter), marker_environment)

    def describe(self) -> str:
        """Return a concise human-readable target description.

        Returns:
            A one-line target summary.
        """
        source = self.interpreter or "current interpreter"
        paths = ", ".join(self.paths or ()) or "runtime search path"
        return f"Target environment: {source}; metadata paths: {paths}"

    def output_environment(self) -> dict[str, object]:
        """Return the target details stored in machine-readable output.

        Returns:
            JSON-compatible target details.
        """
        return {
            "implementation": self.marker_environment["platform_python_implementation"],
            "python_version": self.marker_environment["python_full_version"],
            "platform": self.marker_environment["sys_platform"],
            "interpreter": self.interpreter,
            "paths": list(self.paths or ()),
            "markers": self.marker_environment,
        }


_TARGET_SCRIPT = """
import json
import os
import platform
import sys

version = platform.python_version()
marker_environment = {
    "implementation_name": platform.python_implementation().lower(),
    "implementation_version": version,
    "os_name": os.name,
    "platform_machine": platform.machine(),
    "platform_release": platform.release(),
    "platform_system": platform.system(),
    "platform_version": platform.version(),
    "python_full_version": version,
    "platform_python_implementation": platform.python_implementation(),
    "python_version": ".".join(version.split(".")[:2]),
    "sys_platform": sys.platform,
}
print(json.dumps({"paths": sys.path, "marker_environment": marker_environment}))
"""


def _parse_project_urls(meta: importlib_metadata.PackageMetadata) -> dict[str, str]:
    urls: dict[str, str] = {}
    # importlib.metadata's PackageMetadata is untyped (email.Message based), so
    # get_all yields Any; cast the headers we read into the typed world.
    entries = cast("list[str]", meta.get_all("Project-URL") or [])
    for entry in entries:
        if ", " in entry:
            label, url = entry.split(", ", 1)
            urls[label.strip()] = url.strip()
    return urls


def _parse_keywords(meta: importlib_metadata.PackageMetadata) -> list[str]:
    raw = meta.get("Keywords")
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def _parse_license(
    meta: importlib_metadata.PackageMetadata,
) -> tuple[str | None, Literal["expression", "legacy"] | None]:
    expression = meta.get("License-Expression")
    if expression:
        return expression, "expression"
    legacy = meta.get("License")
    return legacy, "legacy" if legacy else None


def get_package(name: str, *, target: LocalTarget | None = None) -> PackageInfo:
    """Get metadata for a locally installed package.

    Args:
        name: Package name to look up.

    Returns:
        A :class:`PackageInfo` with ``source="local"``.

    Raises:
        PackageNotFoundError: If the package is not installed.
    """
    dist: importlib_metadata.Distribution
    try:  # ruff: ignore[too-many-statements-in-try-clause]
        if target is None or target.paths is None:
            dist = importlib_metadata.distribution(name)
        else:
            found = next(
                (
                    candidate
                    for candidate in importlib_metadata.distributions(
                        path=list(target.paths)
                    )
                    if canonicalize_name(candidate.metadata["Name"])
                    == canonicalize_name(name)
                ),
                None,
            )
            if found is None:
                raise importlib_metadata.PackageNotFoundError(name)  # ruff: ignore[raise-within-try]
            dist = found
    except importlib_metadata.PackageNotFoundError as exc:
        raise PackageNotFoundError(name) from exc

    meta = dist.metadata
    files = [str(f) for f in dist.files] if dist.files else None
    license_value, license_source = _parse_license(meta)
    return PackageInfo(
        name=meta["Name"],
        version=meta["Version"],
        summary=meta.get("Summary"),
        author=meta.get("Author"),
        author_email=meta.get("Author-email"),
        maintainer=meta.get("Maintainer"),
        license=license_value,
        license_source=license_source,
        python_requires=meta.get("Requires-Python"),
        homepage=meta.get("Home-page"),
        project_urls=_parse_project_urls(meta),
        dependencies=list(dist.requires) if dist.requires else [],
        classifiers=meta.get_all("Classifier") or [],
        keywords=_parse_keywords(meta),
        files=files,
        vulnerabilities=[],
        source="local",
        retrieved_at=utc_now(),
    )
