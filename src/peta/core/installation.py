"""How a distribution was installed, and whether its files still match.

Reads only what the distribution's own metadata directory records --
``direct_url.json``, ``INSTALLER``, ``REQUESTED``, ``entry_points.txt``,
``top_level.txt``, and ``RECORD`` -- and the installed files ``RECORD`` names,
never anything outside the selected environment.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import inspect
import json
import sys
from dataclasses import dataclass, field
from itertools import starmap
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from typing_extensions import TypeAliasType

from peta.core.local import find_distribution, legacy_installed_files
from peta.core.redaction import redacted

if TYPE_CHECKING:
    import importlib.metadata as importlib_metadata

    from peta.core.local import LocalTarget

__all__ = [
    "FILE_STATES",
    "EntryPoint",
    "FileState",
    "Installation",
    "InstalledFile",
    "Origin",
    "OriginKind",
    "RecordSource",
    "inspect_installation",
]

OriginKind = TypeAliasType(
    "OriginKind", Literal["index", "vcs", "archive", "directory", "unknown"]
)
"""Where a distribution came from, as ``direct_url.json`` records it.

``index`` means no ``direct_url.json`` exists, which is what an ordinary
index installation leaves -- though an installer that never writes the file
leaves the same thing. ``unknown`` means the file exists but cannot be read.
"""

FileState = TypeAliasType(
    "FileState",
    Literal[
        "verified",
        "mismatch",
        "missing",
        "not_recorded",
        "unverifiable",
        "unchecked",
        "out_of_bounds",
    ],
)
"""What peta could establish about one recorded file.

Kept deliberately distinct: an absent hash (``not_recorded``) says nothing
about corruption, and a hash that was never computed (``unchecked``) is not a
verified one. ``unverifiable`` means a hash was recorded but could not be
checked -- an algorithm peta cannot compute, or a file it cannot read.
``out_of_bounds`` marks a path that resolves outside the
selected environment, which is reported rather than read.
"""

FILE_STATES: Final[tuple[FileState, ...]] = (
    "verified",
    "mismatch",
    "missing",
    "not_recorded",
    "unverifiable",
    "unchecked",
    "out_of_bounds",
)
"""Every file state, in the order human output summarizes them."""

RecordSource = TypeAliasType("RecordSource", Literal["RECORD", "installed-files.txt"])
"""Which listing the installed files came from."""

_CHUNK = 1 << 16
"""Bytes read at a time while hashing, so a large file is never held whole."""


@dataclass(frozen=True)
class Origin:
    """A distribution's origin, from ``direct_url.json``."""

    kind: OriginKind
    url: str | None = None
    editable: bool = False
    vcs: str | None = None
    requested_revision: str | None = None
    commit_id: str | None = None
    archive_hashes: dict[str, str] = field(default_factory=dict)
    subdirectory: str | None = None
    reason: str | None = None
    """Why an ``unknown`` origin could not be read."""


@dataclass(frozen=True)
class EntryPoint:
    """One advertised entry point."""

    group: str
    name: str
    value: str


@dataclass(frozen=True)
class InstalledFile:
    """One file a distribution recorded, and what peta found on disk."""

    path: str
    state: FileState
    size: int | None = None
    """The size on disk, when the file was found within bounds."""
    recorded_size: int | None = None
    recorded_hash: str | None = None
    """The ``RECORD`` hash as ``algorithm=digest``, when one was recorded."""


@dataclass(frozen=True)
class Installation:
    """Origin, installer, and file-integrity evidence for one distribution."""

    name: str
    version: str
    origin: Origin
    installer: str | None
    requested: bool
    """Whether the ``REQUESTED`` marker is present.

    ``False`` is only as strong as the installer: one that never writes the
    marker leaves every distribution looking like a dependency.
    """
    import_packages: list[str]
    entry_points: list[EntryPoint]
    record_source: RecordSource | None
    """Which listing ``files`` came from, or ``None`` when there is none."""
    files: list[InstalledFile]
    hashes_verified: bool
    """Whether recorded hashes were compared, which ``--verify`` opts into."""

    def state_counts(self) -> dict[FileState, int]:
        """Count files per state, including states no file is in.

        Returns:
            One entry per :data:`FILE_STATES` value, in that order.
        """
        return {
            state: sum(file.state == state for file in self.files)
            for state in FILE_STATES
        }

    @property
    def total_size(self) -> int:
        """Sum of the sizes found on disk; missing files contribute nothing."""
        return sum(file.size or 0 for file in self.files)


def _optional_str(data: dict[str, object], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) else None


def _object(value: object) -> dict[str, object] | None:
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def _archive_hashes(info: dict[str, object]) -> dict[str, str]:
    """Collect ``archive_info`` hashes, including the deprecated ``hash`` key.

    Returns:
        Algorithm-to-hex-digest pairs.
    """
    hashes = _object(info.get("hashes")) or {}
    found = {
        str(name): value for name, value in hashes.items() if isinstance(value, str)
    }
    legacy = _optional_str(info, "hash")
    if legacy and "=" in legacy:
        name, digest = legacy.split("=", 1)
        found[name] = found.get(name, digest)
    return found


def _vcs_origin(url: str, info: dict[str, object], sub: str | None) -> Origin:
    return Origin(
        kind="vcs",
        url=url,
        vcs=_optional_str(info, "vcs"),
        requested_revision=_optional_str(info, "requested_revision"),
        commit_id=_optional_str(info, "commit_id"),
        subdirectory=sub,
    )


def _described_origin(data: dict[str, object]) -> Origin:
    """Interpret a decoded ``direct_url.json`` object.

    Returns:
        The origin it describes, or an ``unknown`` one naming the problem.
    """
    raw_url = _optional_str(data, "url")
    if raw_url is None:
        return Origin(kind="unknown", reason="direct_url.json has no url.")
    # Userinfo and token parameters are the installer's record of how the
    # user fetched the project, not metadata the project declared: they are
    # credentials, and would leak into every report of this environment.
    url = redacted(raw_url)
    sub = _optional_str(data, "subdirectory")
    if (vcs := _object(data.get("vcs_info"))) is not None:
        return _vcs_origin(url, vcs, sub)
    if (archive := _object(data.get("archive_info"))) is not None:
        hashes = _archive_hashes(archive)
        return Origin(kind="archive", url=url, archive_hashes=hashes, subdirectory=sub)
    if (directory := _object(data.get("dir_info"))) is not None:
        editable = directory.get("editable") is True
        return Origin(kind="directory", url=url, editable=editable, subdirectory=sub)
    return Origin(kind="unknown", url=url, reason="direct_url.json names no source.")


def _origin(dist: importlib_metadata.Distribution) -> Origin:
    text = dist.read_text("direct_url.json")
    if text is None:
        return Origin(kind="index")
    try:
        data = cast("object", json.loads(text))
    except json.JSONDecodeError:
        return Origin(kind="unknown", reason="direct_url.json is not valid JSON.")
    decoded = _object(data)
    if decoded is None:
        return Origin(kind="unknown", reason="direct_url.json is not an object.")
    return _described_origin(decoded)


def _installer(dist: importlib_metadata.Distribution) -> str | None:
    text = dist.read_text("INSTALLER")
    first = text.strip().splitlines()[0].strip() if text and text.strip() else ""
    return first or None


def _entry_points(dist: importlib_metadata.Distribution) -> list[EntryPoint]:
    found = {
        EntryPoint(group=point.group, name=point.name, value=point.value)
        for point in dist.entry_points
    }
    return sorted(found, key=lambda point: (point.group, point.name))


def _is_metadata_dir(part: str) -> bool:
    return part.endswith((".dist-info", ".egg-info", ".data")) or part in {
        "..",
        "__pycache__",
    }


def _top_level_name(path: str) -> str | None:
    """Name the importable top-level module a recorded file belongs to.

    Returns:
        The module or package name, or ``None`` for metadata, scripts, and
        installer helpers such as an editable install's path hook.
    """
    parts = Path(path).parts
    head = parts[0] if parts else ""
    if not head or _is_metadata_dir(head):
        return None
    name = head if len(parts) > 1 else inspect.getmodulename(head)
    if not name or not name.isidentifier() or name.startswith("__editable__"):
        return None
    return name


def _import_packages(
    dist: importlib_metadata.Distribution, paths: list[str]
) -> list[str]:
    """Map the distribution to the names it makes importable.

    ``top_level.txt`` wins when present, as it does for
    :func:`importlib.metadata.packages_distributions`; otherwise the names
    are inferred from the recorded files.

    Returns:
        Sorted, de-duplicated import names.
    """
    declared = dist.read_text("top_level.txt")
    names: set[str | None] = (
        {line.strip() for line in declared.splitlines()}
        if declared is not None
        else {_top_level_name(path) for path in paths}
    )
    return sorted(name for name in names if name)


def _recorded_size(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def _record_rows(text: str) -> list[tuple[str, int | None, str | None]]:
    """Parse ``RECORD`` without :attr:`importlib.metadata.Distribution.files`.

    From Python 3.12 that property silently drops entries whose file no
    longer exists, which would hide exactly the missing files this inspection
    exists to report.

    Returns:
        ``(path, recorded size, recorded hash)`` for every non-empty row.
    """
    rows: list[tuple[str, int | None, str | None]] = []
    for row in csv.reader(text.splitlines()):
        if not row or not row[0]:
            continue
        # Padded so a row missing its trailing columns reads as unrecorded.
        path, digest, size = [*row, "", ""][:3]
        rows.append((path, _recorded_size(size), digest or None))
    return rows


def _digest(path: Path, algorithm: str) -> str:
    """Hash a file the way ``RECORD`` encodes it: urlsafe base64, unpadded.

    Returns:
        The encoded digest.
    """
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            hasher.update(chunk)
    return base64.urlsafe_b64encode(hasher.digest()).rstrip(b"=").decode("ascii")


def _within(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path.is_relative_to(root) for root in roots)


@dataclass(frozen=True)
class _Checker:
    """Resolves recorded paths and decides each file's state."""

    base: Path
    roots: tuple[Path, ...]
    verify: bool

    def check(
        self,
        path: str,
        recorded_size: int | None = None,
        recorded_hash: str | None = None,
    ) -> InstalledFile:
        recorded = (recorded_size, recorded_hash)
        # ``resolve`` follows symlinks, so a link inside site-packages that
        # points elsewhere is judged by where it leads, not where it sits.
        located = (self.base / path).resolve()
        if not _within(located, self.roots):
            return InstalledFile(path, "out_of_bounds", None, *recorded)
        if not located.is_file():
            return InstalledFile(path, "missing", None, *recorded)
        size = located.stat().st_size
        try:
            state = self._state(located, size, recorded_size, recorded_hash)
        except OSError:
            # Present but unreadable: neither missing nor evidence of a change.
            state = "unverifiable"
        return InstalledFile(path, state, size, *recorded)

    def _state(
        self,
        located: Path,
        size: int,
        recorded_size: int | None,
        recorded_hash: str | None,
    ) -> FileState:
        if recorded_size is not None and size != recorded_size:
            return "mismatch"
        if recorded_hash is None:
            return "not_recorded"
        if not self.verify:
            return "unchecked"
        algorithm, expected = recorded_hash.split("=", 1)
        if algorithm not in hashlib.algorithms_guaranteed:
            return "unverifiable"
        return "verified" if _digest(located, algorithm) == expected else "mismatch"


def _roots(base: Path, prefix: str | None) -> tuple[Path, ...]:
    roots = [base]
    if prefix:
        roots.append(Path(prefix).resolve())
    return tuple(roots)


def _record_files(
    dist: importlib_metadata.Distribution, checker: _Checker
) -> tuple[RecordSource | None, list[InstalledFile]]:
    """Check every file the distribution lists.

    ``RECORD`` is read only when it is non-empty: without it importlib falls
    back to ``SOURCES.txt``, which lists a project's source tree rather than
    what was installed, and reporting those as missing would be false.

    Returns:
        Which listing was used, and one checked entry per listed file.
    """
    record = dist.read_text("RECORD")
    if record:
        return "RECORD", list(starmap(checker.check, _record_rows(record)))
    legacy = legacy_installed_files(dist, skip_missing=False)
    if legacy:
        return "installed-files.txt", [checker.check(path) for path in legacy]
    return None, []


def inspect_installation(
    name: str, *, target: LocalTarget | None = None, verify: bool = False
) -> Installation:
    """Describe how ``name`` was installed and check its recorded files.

    Args:
        name: Distribution name to look up.
        target: The environment to search; the running one when ``None``.
        verify: Compare recorded hashes, reading every in-bounds file.

    Returns:
        The distribution's origin, installer, and file evidence.
    """
    dist = find_distribution(name, target=target)
    base = Path(str(dist.locate_file(""))).resolve()
    prefix = target.prefix if target is not None else sys.prefix
    checker = _Checker(base, _roots(base, prefix), verify)
    record_source, files = _record_files(dist, checker)
    meta = dist.metadata
    return Installation(
        name=meta["Name"],
        version=meta["Version"],
        origin=_origin(dist),
        installer=_installer(dist),
        requested=dist.read_text("REQUESTED") is not None,
        import_packages=_import_packages(dist, [file.path for file in files]),
        entry_points=_entry_points(dist),
        record_source=record_source,
        files=files,
        hashes_verified=verify,
    )
