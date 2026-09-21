"""Local package metadata fetcher using importlib.metadata."""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import] # Controlled interpreter invocation below.
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from packaging.markers import default_environment
from packaging.utils import canonicalize_name

from peta.core.models import PackageInfo
from peta.core.output import utc_now

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["InvalidTargetError", "LocalTarget", "PackageNotFoundError", "get_package"]


class PackageNotFoundError(Exception):
    """Raised when a package is not installed locally."""

    def __init__(self, name: str) -> None:
        """Store the missing package name."""
        self.name: str = name
        super().__init__(f"Package '{name}' is not installed")


class InvalidTargetError(ValueError):
    """Raised when an explicit local-environment target cannot be used."""


_INSPECT_TIMEOUT = 15.0
"""Seconds to wait for a target interpreter to describe itself.

An arbitrary executable -- or a ``sitecustomize`` hook inside an otherwise
valid environment -- can block forever. Without a deadline the command hangs
with no output and no way to tell a slow interpreter from a stuck one.
"""

_REQUIRED_MARKERS = frozenset({
    "platform_python_implementation",
    "python_full_version",
    "sys_platform",
})
"""Marker names :meth:`LocalTarget.output_environment` reads by subscript.

Checked while the payload is still being validated, so a truncated marker
mapping is rejected with a target error instead of surfacing as a ``KeyError``
from deep inside output serialization.
"""

_VERSION_PARTS_WITH_PATCH = 3


def _interpreter_problem(python: str, detail: str) -> str:
    """Compose the message for an unusable ``--python`` target.

    Returns:
        A message naming the interpreter and what is wrong with it.
    """
    return f"Invalid Python interpreter {python!r}: {detail}"


def _all_strings(values: Iterable[object]) -> bool:
    """Report whether every value is a string.

    Returns:
        ``True`` when the iterable is empty or holds only ``str`` values.
    """
    return all(isinstance(value, str) for value in values)


def _run_inspection(interpreter: Path, python: str) -> object:
    """Ask ``interpreter`` to describe itself and decode what it printed.

    Returns:
        The decoded JSON payload, not yet validated.

    Raises:
        InvalidTargetError: If the interpreter cannot be started, exits
            non-zero, exceeds :data:`_INSPECT_TIMEOUT`, or does not print JSON.
    """
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] # Interpreter is the explicit CLI target.
            [str(interpreter), "-c", _TARGET_SCRIPT],
            check=True,
            capture_output=True,
            text=True,
            timeout=_INSPECT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        detail = f"it did not respond within {_INSPECT_TIMEOUT:g}s."
        raise InvalidTargetError(_interpreter_problem(python, detail)) from exc
    except (OSError, subprocess.CalledProcessError) as exc:
        msg = _interpreter_problem(python, "could not inspect it.")
        raise InvalidTargetError(msg) from exc
    try:
        # Cast rather than returned directly: ``json.loads`` is typed ``Any``,
        # and letting that escape would defeat the validation that follows.
        payload = cast("object", json.loads(completed.stdout))
    except json.JSONDecodeError as exc:
        msg = _interpreter_problem(python, "could not inspect it.")
        raise InvalidTargetError(msg) from exc
    return payload


def _validated_markers(marker: object, msg: str) -> dict[str, str]:
    """Check the marker mapping an interpreter reported.

    Returns:
        The marker environment, every name and value a string.

    Raises:
        InvalidTargetError: If the mapping is the wrong shape, holds a
            non-string, or omits a name :data:`_REQUIRED_MARKERS` lists.
    """
    if not isinstance(marker, dict):
        raise InvalidTargetError(msg)
    raw = cast("dict[object, object]", marker)
    usable = (
        _all_strings(raw)
        and _all_strings(raw.values())
        and _REQUIRED_MARKERS.issubset(raw)
    )
    if not usable:
        raise InvalidTargetError(msg)
    return cast("dict[str, str]", raw)


def _validated_paths(search_paths: object, msg: str) -> tuple[str, ...]:
    """Check the search path an interpreter reported.

    Returns:
        The interpreter's ``sys.path`` entries.

    Raises:
        InvalidTargetError: If it is not a list of strings.
    """
    if not isinstance(search_paths, list):
        raise InvalidTargetError(msg)
    raw = cast("list[object]", search_paths)
    if not _all_strings(raw):
        raise InvalidTargetError(msg)
    return tuple(cast("list[str]", raw))


def _validated_inspection(
    payload: object, python: str
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Check an inspection payload before any part of it is trusted.

    ``json.loads`` returns whatever the interpreter chose to print, so every
    layer is checked -- here for the object itself, and in
    :func:`_validated_paths` and :func:`_validated_markers` for what it holds.
    Coercing with ``str`` instead would accept a malformed environment and
    only fail once the bad values had reached the output.

    Returns:
        The interpreter's search paths and its marker environment.

    Raises:
        InvalidTargetError: If the payload is not a JSON object.
    """
    msg = _interpreter_problem(python, "returned invalid environment data.")
    if not isinstance(payload, dict):
        raise InvalidTargetError(msg)
    details = cast("dict[str, object]", payload)
    return (
        _validated_paths(details.get("paths"), msg),
        _validated_markers(details.get("marker_environment"), msg),
    )


def _checked_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve each ``--path`` entry and reject anything that is not a directory.

    Returns:
        The resolved, absolute metadata search paths.

    Raises:
        InvalidTargetError: If a path does not name an existing directory.
    """
    checked: list[str] = []
    for path in paths:
        msg = f"Invalid metadata path {path!r}: expected an existing directory."
        # Emptiness is rejected before resolving, because ``Path("").resolve()``
        # is the working directory: an empty --path would silently mean "here".
        if not path.strip():
            raise InvalidTargetError(msg)
        resolved = Path(path).resolve()
        if not resolved.is_dir():
            raise InvalidTargetError(msg)
        checked.append(str(resolved))
    return tuple(checked)


@dataclass(frozen=True)
class LocalTarget:
    """Metadata paths and marker values used for a local inspection."""

    paths: tuple[str, ...] | None
    interpreter: str | None
    marker_environment: dict[str, str]

    @classmethod
    def create(
        cls,
        python: str | None = None,
        paths: tuple[str, ...] = (),
        python_version: str | None = None,
        platform: str | None = None,
    ) -> LocalTarget:
        """Build a target without implicitly discovering a virtual environment.

        Returns:
            The selected metadata paths and marker environment.

        Raises:
            InvalidTargetError: If a path or interpreter cannot be inspected.
        """
        checked = _checked_paths(paths)
        if python is None:
            marker_environment = {
                key: str(value) for key, value in default_environment().items()
            }
            return cls(
                checked or None,
                None,
                _target_markers(marker_environment, python_version, platform),
            )
        if not python.strip():
            msg = _interpreter_problem(python, "no interpreter path given.")
            raise InvalidTargetError(msg)
        # Do not resolve symlinks: a virtualenv's ``bin/python`` commonly
        # points at its base interpreter, and resolving it loses the venv.
        interpreter = Path(python).absolute()
        if not interpreter.is_file():
            msg = _interpreter_problem(python, "file does not exist.")
            raise InvalidTargetError(msg)
        inspected, marker_environment = _validated_inspection(
            _run_inspection(interpreter, python), python
        )
        return cls(
            checked or inspected,
            str(interpreter),
            _target_markers(marker_environment, python_version, platform),
        )

    def describe(self) -> str:
        """Return a concise human-readable target description.

        Includes the marker values that decide which dependencies a tree
        contains, since with ``--path`` alone they come from the running
        interpreter rather than from anything named on the command line.

        Returns:
            A one-line target summary.
        """
        source = self.interpreter or "current interpreter"
        paths = ", ".join(self.paths or ()) or "runtime search path"
        markers = (
            f"{self.marker_environment['platform_python_implementation']} "
            f"{self.marker_environment['python_full_version']} "
            f"on {self.marker_environment['sys_platform']}"
        )
        return (
            f"Target environment: {source}; metadata paths: {paths}; markers: {markers}"
        )

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


_PLATFORM_MARKERS: Final[dict[str, dict[str, str]]] = {
    "win32": {"os_name": "nt", "platform_system": "Windows"},
    "linux": {"os_name": "posix", "platform_system": "Linux"},
    "darwin": {"os_name": "posix", "platform_system": "Darwin"},
}


def _override_python_version(target: dict[str, str], python_version: str) -> None:
    parts = python_version.split(".")
    if len(parts) not in {2, 3} or not all(part.isdigit() for part in parts):
        msg = f"Invalid Python version {python_version!r}: expected X.Y or X.Y.Z."
        raise InvalidTargetError(msg)
    target["python_version"] = ".".join(parts[:2])
    target["python_full_version"] = (
        python_version
        if len(parts) == _VERSION_PARTS_WITH_PATCH
        else f"{python_version}.0"
    )
    if target.get("platform_python_implementation") == "CPython":
        target["implementation_version"] = target["python_full_version"]


def _override_platform(target: dict[str, str], platform: str) -> None:
    if not platform.strip():
        msg = "Invalid platform '': expected a marker platform."
        raise InvalidTargetError(msg)
    if platform not in _PLATFORM_MARKERS:
        msg = f"Invalid platform {platform!r}: expected win32, linux, or darwin."
        raise InvalidTargetError(msg)
    target["sys_platform"] = platform
    target.update(_PLATFORM_MARKERS[platform])


def _target_markers(
    marker_environment: dict[str, str], python_version: str | None, platform: str | None
) -> dict[str, str]:
    """Apply explicit marker overrides without changing metadata paths.

    Returns:
        The adjusted marker environment.
    """
    target = dict(marker_environment)
    if python_version is not None:
        _override_python_version(target, python_version)
    if platform is not None:
        _override_platform(target, platform)
    return target


_TARGET_SCRIPT = """
import json
import os
import platform
import sys

version = platform.python_version()
implementation = sys.implementation
implementation_version = (
    f"{implementation.version.major}.{implementation.version.minor}."
    f"{implementation.version.micro}"
)
if implementation.version.releaselevel != "final":
    implementation_version += (
        implementation.version.releaselevel[0] + str(implementation.version.serial)
    )
marker_environment = {
    "implementation_name": implementation.name,
    "implementation_version": implementation_version,
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


def _is_named(candidate: importlib_metadata.Distribution, canonical: str) -> bool:
    """Match one enumerated distribution against a canonical package name.

    A directory on the search path can hold a ``.dist-info`` whose metadata
    carries no ``Name``. Skipping it keeps a single corrupt entry from hiding
    every package enumerated after it.

    Returns:
        Whether this candidate is the requested distribution.
    """
    found = cast("str | None", candidate.metadata["Name"])
    return found is not None and canonicalize_name(found) == canonical


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
            canonical = canonicalize_name(name)
            found = next(
                (
                    candidate
                    for candidate in importlib_metadata.distributions(
                        path=list(target.paths)
                    )
                    if _is_named(candidate, canonical)
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
