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
import importlib.metadata as importlib_metadata
import io
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from functools import partial
from itertools import islice, starmap
from pathlib import Path
from typing import IO, TYPE_CHECKING, BinaryIO, Final, Literal, NoReturn, cast
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name
from typing_extensions import TypeAliasType, override

from peta.core.local import (
    METADATA_READ_ERRORS,
    PackageNotFoundError,
    find_distribution,
    legacy_installed_files,
)
from peta.core.redaction import redacted

if TYPE_CHECKING:
    from collections.abc import Iterator
    from importlib.resources.abc import Traversable

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
    "is_local_scheme",
]

OriginKind = TypeAliasType(
    "OriginKind", Literal["index", "vcs", "archive", "directory", "unknown"]
)
"""Where a distribution came from, as ``direct_url.json`` records it.

``index`` means no ``direct_url.json`` exists, which is what an ordinary
index installation leaves -- though an installer that never writes the file
leaves the same thing. ``unknown`` means the file exists but does not
describe a usable origin: it is not valid JSON, names no url, or names no
source.
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
verified one. ``unverifiable`` means the file could not be checked -- its
hash uses an algorithm peta cannot compute, or it cannot be reached or read.
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

_COMPUTABLE: Final[frozenset[str]] = frozenset(hashlib.algorithms_guaranteed) - {
    "shake_128",
    "shake_256",
}
"""Algorithms a ``RECORD`` digest can be checked with.

The SHAKE functions are guaranteed but variable-length: their digest needs a
length ``RECORD`` does not carry, so they are ``unverifiable`` like any other
hash peta cannot recompute.
"""

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
    """Why an origin is ``unknown``."""


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
    """Whether ``--verify`` asked for hashes to be compared.

    Not an attestation on its own: a listing with no recorded hashes compares
    nothing even when this is ``True``. The ``verified`` count says how many
    files actually matched.
    """

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


def _source_origin(url: str, data: dict[str, object]) -> Origin:
    """Pick the origin kind from whichever ``*_info`` object is present.

    Returns:
        The described origin, or an ``unknown`` one when none is present.
    """
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


def is_local_scheme(scheme: str) -> bool:
    """Whether a URL scheme names a path on this machine rather than a host.

    Covers ``file`` and VCS ``+file`` URLs, a bare path with no scheme, and a
    Windows drive letter, which :func:`urllib.parse.urlsplit` reads as one.

    Returns:
        ``True`` for a local scheme.
    """
    return (
        scheme == "file"
        or scheme.endswith("+file")
        or not scheme
        or (len(scheme) == 1 and scheme.isalpha())
    )


def _malformed_authority(url: str) -> bool:
    """Whether a URL's host is missing where it needs one, or present where not.

    An authority whose port is not a number is malformed, and so is a
    network URL without one, as when backslashes stand in for the ``//``
    of ``https://{user}:{token}@host``, puts the userinfo in the path, where
    redaction does not look for it. A scheme-relative ``//host/repo`` names a
    host, but would be shown as a local path, hiding it.

    Returns:
        ``True`` when the URL cannot be reported faithfully.
    """
    parts = urlsplit(url)
    try:
        # ``https://user:secret/path`` has no ``@`` for redaction to find:
        # what looks like a password sits where the port belongs.
        _ = parts.port
    except ValueError:
        return True
    if not parts.scheme:
        return bool(parts.netloc)
    return not parts.netloc and not is_local_scheme(parts.scheme)


def _described_origin(data: dict[str, object]) -> Origin:
    """Interpret a decoded ``direct_url.json`` object.

    Returns:
        The origin it describes, or an ``unknown`` one naming the problem.
    """
    raw_url = _optional_str(data, "url")
    # Blank is no better than absent: it names no origin to report.
    if raw_url is None or not raw_url.strip():
        return Origin(kind="unknown", reason="direct_url.json has no url.")
    # Userinfo and token parameters are the installer's record of how the
    # user fetched the project, not metadata the project declared: they are
    # credentials, and would leak into every report of this environment.
    try:
        url: str | None = redacted(raw_url)
    except ValueError:
        url = None
    # ``redacted`` has already split it, so this cannot raise.
    if url is None or _malformed_authority(raw_url):
        return Origin(kind="unknown", reason="direct_url.json has a malformed url.")
    # Dropped whole: an installer records hashes and the subdirectory under
    # their own keys, so a fragment here holds nothing but, perhaps, a token
    # that ``redacted`` does not look for. The first ``#`` is where
    # :func:`urllib.parse.urlsplit` splits one off too.
    return _source_origin(url.partition("#")[0], data)


_MAX_METADATA_BYTES = 64 * 1024 * 1024
"""The largest file listing read; far above any real ``RECORD``."""

_MAX_CORE_METADATA_BYTES = 64 * 1024 * 1024
"""The largest ``METADATA`` read: it embeds the whole long description."""

_MAX_SMALL_METADATA_BYTES = 1024 * 1024
"""The largest of any other metadata file read; far above any real one.

``INSTALLER``, ``top_level.txt``, ``direct_url.json`` and the like are a few
lines at most, and each expands when split or decoded: held to the listing's
allowance, one could still turn into millions of objects.
"""

_LISTINGS = frozenset({"RECORD", "installed-files.txt"})
"""The metadata files that list every installed file, and so can be large."""

_CORE_METADATA = ("METADATA", "PKG-INFO", "")
"""Where the core metadata can be, in the order the stdlib looks.

``""`` is an ``.egg-info`` that is a single file rather than a directory.
"""


@dataclass(frozen=True)
class _ReadPolicy:
    """How strictly one metadata file is vetted before it is read."""

    limit: int
    """The most bytes read."""

    strict_text: bool = False
    """Whether text that is not valid UTF-8 makes the file unreadable.

    Only for the core metadata, which the specification requires to be
    UTF-8 and which names the package: a damaged ``Name`` is no name. Other
    files are evidence, decoded with replacement characters.
    """

    follow_symlinks: bool = False
    """Whether a symlinked file, or one in a symlinked directory, is read.

    Only for the core metadata, which names the package and nothing else:
    an environment built as a symlink tree, as Nix builds one, links every
    file, and refusing those would hide every package in it. A symlinked
    listing is refused, since it could pass off files outside the
    environment as installed ones.
    """


def _read_policy(name: str) -> _ReadPolicy:
    if name in _LISTINGS:
        return _ReadPolicy(_MAX_METADATA_BYTES)
    if name in _CORE_METADATA:
        return _ReadPolicy(
            _MAX_CORE_METADATA_BYTES, strict_text=True, follow_symlinks=True
        )
    return _ReadPolicy(_MAX_SMALL_METADATA_BYTES)


_MAX_RECORD_ROWS = 1_000_000
"""The most ``RECORD`` or ``installed-files.txt`` entries checked.

Far above any real distribution. The byte limit alone still admits millions
of tiny entries, each one kept in memory and probed on disk.
"""

_MAX_RECORD_ROW_CHARS = 64 * 1024
"""The most characters one ``RECORD`` row may span, newlines included.

Room for the longest path any platform allows, plus its hash and size. A row
has no more fields than characters, so this also bounds how wide the parser
can make it, which the row limit does not.
"""

_LINE_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
"""Every character :meth:`str.splitlines` ends a line at."""

_LINE_BREAK = re.compile(f"[{re.escape(_LINE_BREAKS)}]")


def _line_count_bound(text: str) -> int:
    # An upper bound on ``len(text.splitlines())``, without building them:
    # a ``\r\n`` pair is counted twice, but nothing is missed.
    return sum(map(text.count, _LINE_BREAKS)) + 1


def _oversized_listing(text: str) -> bool:
    """Whether a one-path-per-line listing has too many lines, or too long a one.

    Checked on the text as a whole, before a single line is split off.

    Returns:
        ``True`` when either the line count or a line's length is too great.
    """
    too_long = f"[^{re.escape(_LINE_BREAKS)}]{{{_MAX_RECORD_ROW_CHARS + 1}}}"
    return (
        _line_count_bound(text) > _MAX_RECORD_ROWS
        or re.search(too_long, text) is not None
    )


def _bounded_lines(text: str, spent: list[int]) -> Iterator[str]:
    """Yield the physical lines of ``text``, charging each to the current row.

    The caller zeroes ``spent[0]`` whenever a row ends, so a row that runs
    past :data:`_MAX_RECORD_ROW_CHARS` is refused before the parser has
    built it, however many quoted lines it spans.

    Yields:
        Each line, with its line ending.

    Raises:
        csv.Error: When a row exceeds the character limit.
    """
    for line in io.StringIO(text, newline=""):
        spent[0] += len(line)
        if spent[0] > _MAX_RECORD_ROW_CHARS:
            msg = f"a RECORD row spans more than {_MAX_RECORD_ROW_CHARS} characters"
            raise csv.Error(msg)
        yield line


_ABSENT = (FileNotFoundError, IsADirectoryError, KeyError, NotADirectoryError)
"""What reading a metadata file raises when the distribution has no such file.

The same set :meth:`importlib.metadata.PathDistribution.read_text` treats as
absent, minus ``PermissionError``: an unreadable file is present.
"""


_UNREADABLE = METADATA_READ_ERRORS
"""What reading an unreadable metadata entry can raise."""


def _read_text(dist: importlib_metadata.Distribution, name: str) -> str | None:
    """Read one metadata file as bytes, tolerating content that is not UTF-8.

    ``Distribution.read_text`` decodes strictly, so one corrupt byte would
    abort the whole inspection, and it translates newlines, which turns a
    quoted carriage return inside a ``RECORD`` path into a different path.
    Reading the bytes avoids both; a damaged file is still evidence, decoded
    with replacement characters.

    Returns:
        The file's text; ``None`` when the distribution has no such file, and
        ``""`` when it has one that cannot be read.
    """
    if not isinstance(dist, importlib_metadata.PathDistribution):
        try:
            return dist.read_text(name)
        except UnicodeDecodeError:
            return ""
    # The same private attribute :func:`legacy_installed_files` reads. It may
    # be a ``zipfile.Path`` for a zipped distribution, so it is used as-is.
    folder: Traversable = cast("Traversable", cast("object", dist._path))  # ruff: ignore[private-member-access] # See above.
    return _read_entry(folder.joinpath(name), _read_policy(name))


def _read_bounded(
    entry: Traversable, policy: _ReadPolicy, probed: os.stat_result | None
) -> bytes | None:
    """Read up to ``policy.limit`` bytes from any traversable entry.

    A file on disk is opened only if it is still the one ``probed`` saw, as
    for a hashed file; an archive member has nothing to swap.

    Returns:
        The raw bytes, or ``None`` when the entry exceeds the byte limit.
    """
    chunks: list[bytes] = []
    total = 0
    opened: IO[bytes]
    if isinstance(entry, Path) and probed is not None:
        opened = _open_probed(entry, probed, follow_symlinks=policy.follow_symlinks)
    else:
        opened = entry.open("rb")
    with opened as stream:
        while chunk := stream.read(_CHUNK):
            total += len(chunk)
            if total > policy.limit:
                return None
            chunks.append(chunk)
    return b"".join(chunks)


def _read_entry(entry: Traversable, policy: _ReadPolicy) -> str | None:
    """Read one metadata entry, refusing what :func:`_plain_file` refuses.

    Returns:
        The decoded text; ``None`` when absent, ``""`` when present but
        unreadable or refused.
    """
    probed = None
    if isinstance(entry, Path):
        probed = _plain_file(entry, policy)
        if probed is None:
            return _refused(entry)
    return _decoded(entry, policy, probed)


def _decoded(
    entry: Traversable, policy: _ReadPolicy, probed: os.stat_result | None
) -> str | None:
    try:
        raw = _read_bounded(entry, policy, probed)
    except _ABSENT:
        return None
    except _UNREADABLE:
        return ""
    return "" if raw is None else _text(raw, strict=policy.strict_text)


def _text(raw: bytes, *, strict: bool) -> str:
    try:
        return raw.decode("utf-8", errors="strict" if strict else "replace")
    except UnicodeDecodeError:
        return ""


def _refused(path: Path) -> str | None:
    # Refused is still present, unless nothing at all is there.
    present = path.is_symlink() or path.parent.is_symlink() or path.exists()
    return "" if present else None


def _plain_file(path: Path, policy: _ReadPolicy) -> os.stat_result | None:
    """Report whether a metadata file is safe to read.

    Metadata files are read before any ``RECORD`` containment check applies,
    so they are held to their own: a symlink could expose any readable file
    as recorded paths, and a device such as ``/dev/zero`` would never end.
    Only a regular file of plausible size, not reached through a symlink, is
    read; anything else is present but refused.

    Returns:
        The status of a regular file of at most ``policy.limit`` bytes, not
        reached through a symlink unless the policy allows one, to open it
        against; ``None`` for anything else.
    """
    try:
        info = path.stat() if policy.follow_symlinks else path.lstat()
        parent_info = path.parent.lstat()
    except (OSError, ValueError):
        return None
    plain = (
        stat.S_ISREG(info.st_mode)
        and info.st_size <= policy.limit
        # An ``lstat`` that finds a directory has found no symlink to one.
        and (policy.follow_symlinks or stat.S_ISDIR(parent_info.st_mode))
    )
    return info if plain else None


def _encodable(data: object) -> bool:
    """Whether every string in a decoded JSON document is valid UTF-8.

    A JSON surrogate escape decodes to a lone surrogate, which is only caught
    when a renderer later fails to write it out.

    Returns:
        ``True`` when the document holds no lone surrogate.
    """
    try:
        _ = json.dumps(data, ensure_ascii=False).encode("utf-8")
    except (RecursionError, ValueError):
        return False
    return True


def _origin(dist: importlib_metadata.Distribution) -> Origin:
    text = _read_text(dist, "direct_url.json")
    if text is None:
        return Origin(kind="index")
    try:
        data = cast("object", json.loads(text))
    # ``JSONDecodeError`` is a ``ValueError``, and so is an integer past the
    # digit limit; absurd nesting exhausts the recursion limit instead.
    except (RecursionError, ValueError):
        return Origin(kind="unknown", reason="direct_url.json is not valid JSON.")
    decoded = _object(data)
    if decoded is None:
        return Origin(kind="unknown", reason="direct_url.json is not an object.")
    if not _encodable(decoded):
        return Origin(kind="unknown", reason="direct_url.json has malformed text.")
    return _described_origin(decoded)


def _installer(dist: importlib_metadata.Distribution) -> str | None:
    text = _read_text(dist, "INSTALLER")
    # Split once, not into every line: only the first names the installer.
    first = _LINE_BREAK.split((text or "").strip(), maxsplit=1)[0].strip()
    return first or None


_MAX_ENTRY_POINT_LINES = 100_000
"""The most ``entry_points.txt`` lines parsed; far above any real distribution.

The byte limit alone still admits millions of tiny entries, each one parsed
into an object and kept.
"""


class _Vetted(importlib_metadata.Distribution):
    """Hands a stdlib metadata parser one file's text, already vetted.

    Asking the distribution instead would have it reopen the file, after
    :func:`_read_text` checked it: whatever had been swapped in since, a
    symlink, a device, or a far larger file, would be read unchecked.
    """

    def __init__(self, filename: str, text: str) -> None:
        self._filename: str = filename
        self._text: str = text

    @override
    def read_text(self, filename: str) -> str | None:
        return self._text if filename == self._filename else None

    @override
    def locate_file(self, path: str | os.PathLike[str]) -> NoReturn:
        raise NotImplementedError(path)


def _entry_points(dist: importlib_metadata.Distribution) -> list[EntryPoint]:
    text = _read_text(dist, "entry_points.txt")
    # Each line is at most one entry point, so counting lines bounds what the
    # parser would build without running it.
    if not text or _line_count_bound(text) > _MAX_ENTRY_POINT_LINES:
        return []
    try:
        points = _Vetted("entry_points.txt", text).entry_points
    # The stdlib parser raises ``TypeError`` for a line without ``=``.
    except (TypeError, UnicodeDecodeError, ValueError):
        return []
    found = {
        EntryPoint(group=point.group, name=point.name, value=point.value)
        for point in points
    }
    return sorted(found, key=lambda point: (point.group, point.name, point.value))


def _is_metadata_dir(part: str) -> bool:
    return part.endswith((".dist-info", ".egg-info", ".data")) or part in {
        "..",
        "__pycache__",
    }


_SOURCE_SUFFIXES = frozenset({".py", ".pyw", ".pyc"})
"""File extensions of a top-level source or bytecode module."""

_EXTENSION_SUFFIXES = (".so", ".pyd")
"""File extensions of a top-level extension module, on any platform.

Matched by extension alone rather than :func:`inspect.getmodulename`, which
knows only the running interpreter's ABI tags: the target's
``foo.cpython-311-x86_64-linux-gnu.so`` would not name ``foo`` there.
"""


def _module_name(filename: str) -> str | None:
    # A module name holds no dot, so an extension's ABI tag is whatever
    # follows the first. A source file has no tag: ``foo.bar.py`` is not
    # ``foo``, and its stem fails the identifier check that follows.
    if filename.endswith(_EXTENSION_SUFFIXES):
        return filename.split(".", 1)[0]
    stem, dot, suffix = filename.rpartition(".")
    return stem if dot and f".{suffix}" in _SOURCE_SUFFIXES else None


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
    name = head if len(parts) > 1 else _module_name(head)
    if not name or not name.isidentifier() or name.startswith("__editable__"):
        return None
    return name


def _import_packages(
    dist: importlib_metadata.Distribution, paths: list[str]
) -> list[str]:
    """Map the distribution to the names it makes importable.

    A non-empty ``top_level.txt`` wins, as it does for
    :func:`importlib.metadata.packages_distributions`; otherwise the names
    are inferred from the recorded files.

    Returns:
        Sorted, de-duplicated import names.
    """
    # An empty declaration names nothing, so it does not override inference.
    declared = (_read_text(dist, "top_level.txt") or "").split()
    names: set[str | None] = {*declared} or {_top_level_name(path) for path in paths}
    return sorted(name for name in names if name)


def _recorded_size(value: str) -> int | None:
    # ``isdigit`` alone admits characters such as "²" that ``int`` rejects,
    # and ``int`` refuses digit strings past ``sys.get_int_max_str_digits``.
    if not (value.isascii() and value.isdigit()):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _record_rows(text: str) -> list[tuple[str, int | None, str | None]]:
    """Parse ``RECORD`` without :attr:`importlib.metadata.Distribution.files`.

    From Python 3.12 that property silently drops entries whose file no
    longer exists, which would hide exactly the missing files this inspection
    exists to report.

    Returns:
        ``(path, recorded size, recorded hash)`` for every non-empty row.

    Raises:
        csv.Error: When a row is malformed or too long, or there are too
            many rows.
    """
    rows: list[tuple[str, int | None, str | None]] = []
    # Read as a stream, not pre-split lines: a quoted path may itself hold a
    # newline, and splitting first would silently drop it.
    # ``strict`` makes an unterminated quote an error, instead of folding
    # every later row silently into one field.
    spent = [0]
    reader = csv.reader(_bounded_lines(text, spent), strict=True)
    for row in islice(reader, _MAX_RECORD_ROWS):
        spent[0] = 0
        if not row or not row[0]:
            continue
        # Padded so a row missing its trailing columns reads as unrecorded.
        path, digest, size = (*row[:3], "", "")[:3]
        rows.append((path, _recorded_size(size), digest or None))
    if next(reader, None) is not None:
        msg = f"RECORD has more than {_MAX_RECORD_ROWS} rows"
        raise csv.Error(msg)
    return rows


_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
_OPEN_FLAGS = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_BINARY", 0)
"""Read-only, never through a final symlink where the platform can refuse one."""

_DIRECTORY_FLAGS = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_DIRECTORY", 0)
"""A directory to walk through, refused if it is a symlink."""

_WALKABLE = os.open in os.supports_dir_fd and bool(_NOFOLLOW)
"""Whether a path can be opened one component at a time, following none.

Not on Windows, which has no ``dir_fd``: there, the opened handle is asked
for its final path instead, by :func:`_open_then_locate`.
"""


_FINAL_PATH_CHARS = 32_768
"""Room for the longest path Windows allows, with its extended-length prefix."""

if sys.platform == "win32":  # pragma: no cover - exercised by the Windows jobs
    import ctypes.wintypes
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _get_final_path = _kernel32.GetFinalPathNameByHandleW
    _get_final_path.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
    ]
    _get_final_path.restype = ctypes.wintypes.DWORD

    def _final_path(descriptor: int) -> Path | None:
        """Ask Windows where an open file is, whatever path reached it.

        Returns:
            The file's path with every link resolved, or ``None`` when
            Windows cannot say.
        """
        buffer = ctypes.create_unicode_buffer(_FINAL_PATH_CHARS)
        handle = msvcrt.get_osfhandle(descriptor)
        length = cast("int", _get_final_path(handle, buffer, _FINAL_PATH_CHARS, 0))
        if not 0 < length < _FINAL_PATH_CHARS:
            return None
        name = ctypes.wstring_at(buffer, length)
        if name.startswith("\\\\?\\UNC\\"):
            return Path("\\\\" + name.removeprefix("\\\\?\\UNC\\"))
        return Path(name.removeprefix("\\\\?\\"))

else:  # pragma: no cover - never called where the walk is possible

    def _final_path(descriptor: int) -> Path | None:
        del descriptor
        return None


def _open_then_locate(root: Path, path: Path) -> int:  # pragma: no cover - Windows
    """Open ``path``, then refuse it unless the handle really lies under ``root``.

    For where the walk of :func:`_open_beneath` is not available: the path
    was followed wherever its directories now lead, so the open handle is
    asked where it ended up, which no later swap can change.

    Returns:
        A descriptor for the file.
    """
    descriptor = os.open(path, _OPEN_FLAGS)
    try:
        _ensure_located_beneath(descriptor, path, root)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _ensure_located_beneath(  # pragma: no cover - Windows
    descriptor: int, path: Path, root: Path
) -> None:
    """Raise unless an open file lies under ``root``.

    Raises:
        OSError: When it is elsewhere, or its location cannot be told.
    """
    final = _final_path(descriptor)
    if final is None or not final.is_relative_to(root):
        msg = f"{path} led outside {root} while it was being checked"
        raise OSError(msg)


def _open_beneath(root: Path, path: Path) -> int:  # pragma: no cover - POSIX
    """Open ``path`` by walking down from ``root``, following no symlink.

    ``O_NOFOLLOW`` guards only the last component: a directory swapped for a
    link to somewhere else after containment was checked would otherwise be
    followed, and the file it leads to opened as though it were inside.

    Returns:
        A descriptor for the file.
    """
    *directories, name = path.relative_to(root).parts
    descriptor = os.open(root, _DIRECTORY_FLAGS)
    try:
        for directory in directories:
            child = os.open(directory, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return os.open(name, _OPEN_FLAGS, dir_fd=descriptor)
    finally:
        os.close(descriptor)


_open_within = _open_beneath if _WALKABLE else _open_then_locate
"""Open a file found under a root, so that it cannot turn out to lie elsewhere."""


def _open_probed(
    path: Path,
    probed: os.stat_result,
    *,
    follow_symlinks: bool = False,
    beneath: Path | None = None,
) -> BinaryIO:
    """Open the very file :func:`_probe` saw, not whatever is there now.

    The path was checked for containment before it is opened, and an
    installation being modified meanwhile could swap in a symlink to
    ``/dev/zero`` or a file outside it. Comparing the open descriptor with
    the probe catches that, whichever path component was swapped.

    ``beneath`` is a root the path was found inside, to walk down from where
    the platform allows it.

    Returns:
        The open file.
    """
    flags = _OPEN_FLAGS & ~_NOFOLLOW if follow_symlinks else _OPEN_FLAGS
    descriptor = (
        os.open(path, flags) if beneath is None else _open_within(beneath, path)
    )
    try:
        _ensure_probed(descriptor, path, probed)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_probed(descriptor: int, path: Path, probed: os.stat_result) -> None:
    """Raise unless an open descriptor is the regular file that was probed.

    Raises:
        OSError: When it is some other file.
    """
    opened = os.fstat(descriptor)
    if not (stat.S_ISREG(opened.st_mode) and os.path.samestat(opened, probed)):
        msg = f"{path} changed while it was being checked"
        raise OSError(msg)


def _digest(path: Path, algorithm: str, probed: os.stat_result, root: Path) -> str:
    """Hash a file the way ``RECORD`` encodes it: urlsafe base64, unpadded.

    Reads no more than the probed size, and one byte past it to notice a file
    that grew, so nothing endless can hold the check.

    Returns:
        The encoded digest.

    Raises:
        OSError: When the file changed since it was probed.
    """
    hasher = hashlib.new(algorithm)
    with _open_probed(path, probed, beneath=root) as handle:
        remaining = probed.st_size + 1
        while remaining and (chunk := handle.read(min(_CHUNK, remaining))):
            remaining -= len(chunk)
            hasher.update(chunk)
    if not remaining:
        msg = f"{path} grew while it was being checked"
        raise OSError(msg)
    return base64.urlsafe_b64encode(hasher.digest()).rstrip(b"=").decode("ascii")


_UNRESOLVABLE = (OSError, RuntimeError, ValueError)
"""What resolving a hostile ``RECORD`` path can raise.

``ValueError`` for an embedded NUL byte, ``RuntimeError`` for a symlink loop
on Python 3.11 and 3.12, and ``OSError`` for other resolution failures.
"""


def _resolved(path: Path) -> Path | None:
    """Resolve a recorded path, or ``None`` when it cannot be placed.

    A path that cannot be resolved cannot be shown to lie inside the
    environment, so it is treated like one that lies outside it: reported,
    never read.

    Returns:
        The absolute, symlink-free path, if there is one.
    """
    try:
        return path.resolve()
    except _UNRESOLVABLE:
        return None


def _within(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path.is_relative_to(root) for root in roots)


@dataclass(frozen=True)
class _Checker:
    """Resolves recorded paths and decides each file's state."""

    base: Path
    roots: tuple[Path, ...]
    verify: bool
    readable: bool = True
    """Whether ``base`` is a directory peta can read files under.

    ``False`` for a distribution found inside a zip on the search path:
    its files are archive members, which are reported rather than read.
    """

    def check(
        self,
        path: str,
        recorded_size: int | None = None,
        recorded_hash: str | None = None,
    ) -> InstalledFile:
        recorded = (recorded_size, recorded_hash)
        if not self.readable:
            return InstalledFile(path, "unverifiable", None, *recorded)
        # ``resolve`` follows symlinks, so a link inside site-packages that
        # points elsewhere is judged by where it leads, not where it sits.
        located = _resolved(self.base / path)
        if located is None or not _within(located, self.roots):
            return InstalledFile(path, "out_of_bounds", None, *recorded)
        probed = _probe(located)
        if isinstance(probed, str):
            return InstalledFile(path, probed, None, *recorded)
        size = probed.st_size
        try:
            state = self._state(located, probed, recorded_size, recorded_hash)
        # ``ValueError``: a FIPS build lists md5 as guaranteed yet refuses to
        # construct it, which leaves the digest just as uncomputable.
        except (OSError, ValueError):
            # Present but unreadable: neither missing nor evidence of a change.
            state = "unverifiable"
        return InstalledFile(path, state, size, *recorded)

    def _state(
        self,
        located: Path,
        probed: os.stat_result,
        recorded_size: int | None,
        recorded_hash: str | None,
    ) -> FileState:
        if recorded_size is not None and probed.st_size != recorded_size:
            return "mismatch"
        if recorded_hash is None:
            return "not_recorded"
        if not self.verify:
            return "unchecked"
        name, separator, expected = recorded_hash.partition("=")
        algorithm = name.lower()
        if not separator or algorithm not in _COMPUTABLE:
            return "unverifiable"
        # Within one of the roots: ``check`` placed it there.
        root = next(root for root in self.roots if located.is_relative_to(root))
        digest = _digest(located, algorithm, probed, root)
        return "verified" if digest == expected else "mismatch"


def _probe(located: Path) -> os.stat_result | FileState:
    """Stat a located file once, telling absence from inaccessibility.

    ``Path.is_file`` cannot be used: before 3.14 it re-raises errors such as
    EACCES, and from 3.14 it swallows them, reporting an unreachable file as
    absent. One ``lstat`` answers the same way on every version; the path is
    already resolved, so a symlink found there now was swapped in since.

    Returns:
        The file's status, or the state that stands in for one: ``missing``
        when nothing regular is there, ``unverifiable`` when it cannot be
        reached.
    """
    try:
        info = located.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except (OSError, ValueError):
        return "unverifiable"
    return info if stat.S_ISREG(info.st_mode) else "missing"


_VERSIONED_PYTHON = re.compile(r"python(?:\d+(?:\.\d+)*t?)?", re.IGNORECASE)
"""A ``pythonX.Y``, ``python``, or ``PythonXY`` directory in a scheme layout.

The optional ``t`` is the free-threaded ABI suffix, as in ``python3.13t``.
"""


_LIBRARY_DIRS = frozenset({"lib", "lib64"})
"""Library directory names; ``lib64`` is the platlib on Fedora and RHEL."""


def _scheme_root(base: Path) -> Path | None:
    """Find the installation scheme a ``site-packages`` directory belongs to.

    Console scripts are installed beside the scheme's library directory, not
    inside it, so their ``RECORD`` rows climb out of ``site-packages``. The
    scheme root bounds them for every standard layout, including a user
    install, whose scripts live under the user base rather than
    ``sys.prefix``:

    * ``<root>/lib/pythonX.Y/site-packages`` (or ``lib64``) -- POSIX
      prefixes, venvs, and
      ``~/.local``; ``<root>/lib/python/site-packages`` for a macOS
      framework user install;
    * ``<root>/Lib/site-packages`` -- Windows prefixes and venvs;
    * ``<root>/PythonXY/site-packages`` -- the Windows user site, whose
      data files go straight into the user base ``<root>``.

    Returns:
        The scheme root, or ``None`` when ``base`` follows none of them.
    """
    if base.name.lower() not in {"site-packages", "dist-packages"}:
        return None
    parent = base.parent
    if parent.name.lower() in _LIBRARY_DIRS:
        return parent.parent
    if not _VERSIONED_PYTHON.fullmatch(parent.name):
        return None
    grandparent = parent.parent
    return (
        grandparent.parent if grandparent.name.lower() in _LIBRARY_DIRS else grandparent
    )


def _roots(base: Path, prefix: str | None) -> tuple[Path, ...]:
    candidates = [_scheme_root(base), _resolved(Path(prefix)) if prefix else None]
    return (base, *(root for root in candidates if root is not None))


def _recorded_files(
    record: str, checker: _Checker
) -> tuple[RecordSource | None, list[InstalledFile]]:
    """Check every file a present ``RECORD`` lists.

    Returns:
        ``RECORD`` and one checked entry per row, or no listing at all when
        the file is empty, unreadable, or unparsable.
    """
    try:
        rows = _record_rows(record)
    except csv.Error:
        # An unterminated quote, an oversized field, or too many rows or
        # columns: the listing as a whole is unusable.
        return None, []
    return ("RECORD", list(starmap(checker.check, rows))) if rows else (None, [])


def _record_files(
    dist: importlib_metadata.Distribution, checker: _Checker
) -> tuple[RecordSource | None, list[InstalledFile]]:
    """Check every file the distribution lists.

    A present ``RECORD`` is authoritative even when it is empty or cannot be
    read: falling back would let a stray ``installed-files.txt`` beside it
    pass for the real listing. Only an absent one falls back, and never to
    ``SOURCES.txt``, which lists a project's source tree rather than what was
    installed.

    Returns:
        Which listing was used, and one checked entry per listed file.
    """
    record = _read_text(dist, "RECORD")
    if record is not None:
        return _recorded_files(record, checker)
    # Vetted and bounded here, then parsed from this same text, as for entry
    # points: the file is not read a second time. Its lines bound its
    # entries, so they are counted before any is built.
    legacy_text = _read_text(dist, "installed-files.txt")
    if not legacy_text or _oversized_listing(legacy_text):
        return None, []
    legacy = legacy_installed_files(dist, skip_missing=False, listing=legacy_text)
    if legacy:
        return "installed-files.txt", [checker.check(path) for path in legacy]
    return None, []


_HEADER_END = re.compile(r"\r?\n\r?\n")
"""The blank line that ends the core metadata's headers."""

_CORE_FIELDS = ("name", "version")
"""The core metadata fields every report needs."""

_MAX_FIELD_CHARS = 256
"""The longest ``Name`` or ``Version`` accepted; far above any real one."""

_CORE_FIELD = re.compile(
    rf"^(name|version)[ \t]*:[ \t]*([^\r\n]{{0,{_MAX_FIELD_CHARS + 1}}})",
    re.IGNORECASE | re.MULTILINE,
)
"""A ``Name`` or ``Version`` header, capturing one character past the limit.

A continuation line starts with whitespace, so it never matches.
"""


def _core_fields(dist: importlib_metadata.Distribution) -> dict[str, str]:
    """Read ``Name`` and ``Version`` from vetted core metadata, and nothing else.

    Not handed to the email parser, which builds an object for every header
    and keeps every value however long: only the header block is scanned,
    for the first of each field, and a value past :data:`_MAX_FIELD_CHARS`
    counts as none at all.

    Returns:
        ``name`` and ``version``, lowercased, as far as they were found.
    """
    text = next(filter(None, map(partial(_read_text, dist), _CORE_METADATA)), "")
    headers = _HEADER_END.split(text, maxsplit=1)[0]
    found: dict[str, str] = {}
    for match in _CORE_FIELD.finditer(headers):
        # Judged before stripping: the capture stops one past the limit, so
        # a stripped one could look short however long the value ran.
        raw = match[2]
        usable = raw.strip() if len(raw) <= _MAX_FIELD_CHARS else ""
        _ = found.setdefault(match[1].lower(), usable)
        if len(found) == len(_CORE_FIELDS):
            break
    return found


def _vetted_name(dist: importlib_metadata.Distribution) -> str | None:
    return _core_fields(dist).get("name") or None


def _name_and_version(
    dist: importlib_metadata.Distribution, name: str
) -> tuple[str, str]:
    """Read the two core metadata fields every report needs.

    Read through :func:`_read_text`, as every other metadata file is. A
    distribution whose ``METADATA`` cannot be read, lacks either field, or
    names another package is not the one asked for, just as
    :func:`find_distribution` skips one whose metadata has no name.

    Returns:
        The distribution's name and version.

    Raises:
        PackageNotFoundError: When either is unreadable, missing, blank, or
            too long, or the name is not ``name``.
    """
    found = _core_fields(dist)
    fields = [found.get(key, "") for key in _CORE_FIELDS]
    # The runtime lookup matches the directory name alone, which need not be
    # the package the metadata names.
    if not all(fields) or canonicalize_name(fields[0]) != canonicalize_name(name):
        raise PackageNotFoundError(name)
    return fields[0], fields[1]


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
    dist = find_distribution(name, target=target, name_of=_vetted_name)
    located = dist.locate_file("")
    # A ``zipfile.Path`` for a distribution inside a zip on the search path.
    readable = isinstance(located, Path)
    base = Path(str(located)).resolve()
    prefix = target.prefix if target is not None else sys.prefix
    checker = _Checker(base, _roots(base, prefix), verify, readable)
    record_source, files = _record_files(dist, checker)
    found_name, version = _name_and_version(dist, name)
    return Installation(
        name=found_name,
        version=version,
        origin=_origin(dist),
        installer=_installer(dist),
        requested=_read_text(dist, "REQUESTED") is not None,
        import_packages=_import_packages(dist, [file.path for file in files]),
        entry_points=_entry_points(dist),
        record_source=record_source,
        files=files,
        hashes_verified=verify,
    )
