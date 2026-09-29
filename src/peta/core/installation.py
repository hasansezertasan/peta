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
import lzma
import re
import stat
import sys
import zipfile
import zlib
from dataclasses import dataclass, field
from itertools import islice, starmap
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast
from urllib.parse import urlsplit

from typing_extensions import TypeAliasType

from peta.core.local import find_distribution, legacy_installed_files
from peta.core.redaction import redacted

if TYPE_CHECKING:
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


def _hides_userinfo(url: str) -> bool:
    """Whether a network URL's authority is where a credential would sit.

    Without one, as when backslashes stand in for the ``//`` of
    ``https://{user}:{token}@host``, the userinfo lands in the path, where
    redaction does not look for it.

    Returns:
        ``True`` when the URL is not local and has no authority.
    """
    parts = urlsplit(url)
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
    if url is None or _hides_userinfo(raw_url):
        return Origin(kind="unknown", reason="direct_url.json has a malformed url.")
    # Dropped whole: an installer records hashes and the subdirectory under
    # their own keys, so a fragment here holds nothing but, perhaps, a token
    # that ``redacted`` does not look for. The first ``#`` is where
    # :func:`urllib.parse.urlsplit` splits one off too.
    return _source_origin(url.partition("#")[0], data)


_MAX_METADATA_BYTES = 64 * 1024 * 1024
"""The largest file listing read; far above any real ``RECORD``."""

_MAX_SMALL_METADATA_BYTES = 1024 * 1024
"""The largest of any other metadata file read; far above any real one.

``INSTALLER``, ``top_level.txt``, ``direct_url.json`` and the like are a few
lines at most, and each expands when split or decoded: held to the listing's
allowance, one could still turn into millions of objects.
"""

_LISTINGS = frozenset({"RECORD", "installed-files.txt"})
"""The metadata files that list every installed file, and so can be large."""

_MAX_RECORD_ROWS = 1_000_000
"""The most ``RECORD`` rows checked; far above any real distribution.

The byte limit alone still admits millions of tiny rows, each one kept in
memory and probed on disk.
"""

_ABSENT = (FileNotFoundError, IsADirectoryError, KeyError, NotADirectoryError)
"""What reading a metadata file raises when the distribution has no such file.

The same set :meth:`importlib.metadata.PathDistribution.read_text` treats as
absent, minus ``PermissionError``: an unreadable file is present.
"""

_UNREADABLE = (
    OSError,
    RuntimeError,
    ValueError,
    lzma.LZMAError,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
)
"""What reading an unreadable metadata entry can raise.

A zipped member can also fail to decompress: ``RuntimeError`` when it is
encrypted, ``NotImplementedError`` (a ``RuntimeError``) for a compression
method :mod:`zipfile` lacks, and ``LZMAError`` or ``zlib.error`` for a
corrupt stream.
"""


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
    limit = _MAX_METADATA_BYTES if name in _LISTINGS else _MAX_SMALL_METADATA_BYTES
    return _read_entry(folder.joinpath(name), limit)


def _read_bounded(entry: Traversable, limit: int) -> bytes | None:
    """Read up to ``limit`` bytes from any traversable entry.

    Returns:
        The raw bytes, or ``None`` when the entry exceeds the byte limit.
    """
    chunks: list[bytes] = []
    total = 0
    with entry.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            total += len(chunk)
            if total > limit:
                return None
            chunks.append(chunk)
    return b"".join(chunks)


def _read_entry(entry: Traversable, limit: int) -> str | None:
    """Read one metadata entry, refusing what :func:`_plain_file` refuses.

    Returns:
        The decoded text; ``None`` when absent, ``""`` when present but
        unreadable or refused.
    """
    if isinstance(entry, Path) and not _plain_file(entry, limit):
        return (
            ""
            if entry.is_symlink() or entry.parent.is_symlink() or entry.exists()
            else None
        )
    try:
        raw = _read_bounded(entry, limit)
    except _ABSENT:
        return None
    except _UNREADABLE:
        return ""
    if raw is None:
        return ""
    return raw.decode("utf-8", errors="replace")


def _plain_file(path: Path, limit: int) -> bool:
    """Report whether a metadata file is safe to read.

    Metadata files are read before any ``RECORD`` containment check applies,
    so they are held to their own: a symlink could expose any readable file
    as recorded paths, and a device such as ``/dev/zero`` would never end.
    Only a regular file of plausible size, not reached through a symlink, is
    read; anything else is present but refused.

    Returns:
        ``True`` for a regular, non-symlinked file of at most ``limit``
        bytes.
    """
    try:
        info = path.lstat()
        parent_info = path.parent.lstat()
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and stat.S_ISDIR(parent_info.st_mode)
        and not stat.S_ISLNK(parent_info.st_mode)
        and info.st_size <= limit
    )


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
    first = text.strip().splitlines()[0].strip() if text and text.strip() else ""
    return first or None


_MAX_ENTRY_POINT_LINES = 100_000
"""The most ``entry_points.txt`` lines parsed; far above any real distribution.

The byte limit alone still admits millions of tiny entries, each one parsed
into an object and kept.
"""


def _entry_points(dist: importlib_metadata.Distribution) -> list[EntryPoint]:
    # Vetted through :func:`_read_text` first: the stdlib parser below reads
    # the file itself, and would follow a symlink or read a device.
    text = _read_text(dist, "entry_points.txt")
    # Each line is at most one entry point, so counting lines bounds what the
    # parser would build without running it.
    if not text or text.count("\n") > _MAX_ENTRY_POINT_LINES:
        return []
    try:
        points = dist.entry_points
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


_MODULE_SUFFIXES = (".py", ".pyw", ".pyc", ".so", ".pyd")
"""File extensions of a top-level module, on any platform and Python.

Matched by extension alone rather than :func:`inspect.getmodulename`, which
knows only the running interpreter's ABI tags: the target's
``foo.cpython-311-x86_64-linux-gnu.so`` would not name ``foo`` there.
"""


def _module_name(filename: str) -> str | None:
    # A module name holds no dot, so an ABI tag is whatever follows the first.
    return filename.split(".", 1)[0] if filename.endswith(_MODULE_SUFFIXES) else None


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
        csv.Error: When a row is malformed or there are too many rows.
    """
    rows: list[tuple[str, int | None, str | None]] = []
    # Read as a stream, not pre-split lines: a quoted path may itself hold a
    # newline, and splitting first would silently drop it.
    # ``strict`` makes an unterminated quote an error, instead of folding
    # every later row silently into one field.
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    for row in islice(reader, _MAX_RECORD_ROWS):
        if not row or not row[0]:
            continue
        # Padded so a row missing its trailing columns reads as unrecorded.
        path, digest, size = [*row, "", ""][:3]
        rows.append((path, _recorded_size(size), digest or None))
    if next(reader, None) is not None:
        msg = f"RECORD has more than {_MAX_RECORD_ROWS} rows"
        raise csv.Error(msg)
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
        size = probed
        try:
            state = self._state(located, size, recorded_size, recorded_hash)
        # ``ValueError``: a FIPS build lists md5 as guaranteed yet refuses to
        # construct it, which leaves the digest just as uncomputable.
        except (OSError, ValueError):
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
        name, separator, expected = recorded_hash.partition("=")
        algorithm = name.lower()
        if not separator or algorithm not in _COMPUTABLE:
            return "unverifiable"
        return "verified" if _digest(located, algorithm) == expected else "mismatch"


def _probe(located: Path) -> int | FileState:
    """Stat a located file once, telling absence from inaccessibility.

    ``Path.is_file`` cannot be used: before 3.14 it re-raises errors such as
    EACCES, and from 3.14 it swallows them, reporting an unreachable file as
    absent. One ``stat`` answers the same way on every version.

    Returns:
        The file's size, or the state that stands in for one: ``missing``
        when nothing regular is there, ``unverifiable`` when it cannot be
        reached.
    """
    try:
        info = located.stat()
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except (OSError, ValueError):
        return "unverifiable"
    return info.st_size if stat.S_ISREG(info.st_mode) else "missing"


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
    * ``<root>/PythonXY/site-packages`` -- the Windows user site.

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
    return grandparent.parent if grandparent.name.lower() in _LIBRARY_DIRS else parent


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
        # An unterminated quote, an oversized field, or too many rows: no
        # row after it can be trusted, so the listing as a whole is unusable.
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
    # Vetted first, as for entry points: the legacy reader opens it directly.
    if not _read_text(dist, "installed-files.txt"):
        return None, []
    try:
        legacy = legacy_installed_files(dist, skip_missing=False)
    except UnicodeDecodeError:
        legacy = None
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
    located = dist.locate_file("")
    # A ``zipfile.Path`` for a distribution inside a zip on the search path.
    readable = isinstance(located, Path)
    base = Path(str(located)).resolve()
    prefix = target.prefix if target is not None else sys.prefix
    checker = _Checker(base, _roots(base, prefix), verify, readable)
    record_source, files = _record_files(dist, checker)
    meta = dist.metadata
    return Installation(
        name=meta["Name"],
        version=meta["Version"],
        origin=_origin(dist),
        installer=_installer(dist),
        requested=_read_text(dist, "REQUESTED") is not None,
        import_packages=_import_packages(dist, [file.path for file in files]),
        entry_points=_entry_points(dist),
        record_source=record_source,
        files=files,
        hashes_verified=verify,
    )
