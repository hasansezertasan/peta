"""Format-agnostic derivations shared by the human ``origin`` renderers.

As with :mod:`peta.cli.output.summary`, the Rich, text, and Markdown views
differ only in how they draw rows. Deriving them once here keeps one
installation from being described differently per ``--format``.

Human output never prints a local filesystem path in full: a ``file://``
origin is shown by its final directory name. JSON keeps the structured URL.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from rich.filesize import decimal

from peta.core.installation import FILE_STATES

if TYPE_CHECKING:
    from peta.core.installation import FileState, Installation, InstalledFile, Origin

__all__ = [
    "describe_origin",
    "flagged_files",
    "installation_notes",
    "installation_rows",
]

_FLAGGED: frozenset[FileState] = frozenset({
    "mismatch",
    "missing",
    "unverifiable",
    "out_of_bounds",
})
"""States worth listing file by file; the rest are only counted."""

_COMMIT_WIDTH = 12


def _display_url(url: str | None) -> str:
    """Show where an origin points without exposing a local path.

    Returns:
        The final path component for a ``file://`` URL, the URL otherwise.
    """
    if not url:
        return "-"
    parts = urlsplit(url)
    if parts.scheme != "file":
        return url
    name = PurePosixPath(unquote(parts.path)).name
    return f".../{name}" if name else "local path"


def _subdirectory(origin: Origin) -> str:
    return f" [subdirectory {origin.subdirectory}]" if origin.subdirectory else ""


def _vcs(origin: Origin) -> str:
    text = f"{origin.vcs or 'VCS'} {_display_url(origin.url)}"
    if origin.requested_revision:
        text += f" @ {origin.requested_revision}"
    if origin.commit_id:
        text += f" -> {origin.commit_id[:_COMMIT_WIDTH]}"
    return text


def _archive(origin: Origin) -> str:
    text = f"archive {_display_url(origin.url)}"
    if origin.archive_hashes:
        name, digest = min(origin.archive_hashes.items())
        text += f" ({name}:{digest[:_COMMIT_WIDTH]}...)"
    return text


def _directory(origin: Origin) -> str:
    text = f"local directory {_display_url(origin.url)}"
    return f"{text} (editable)" if origin.editable else text


def describe_origin(origin: Origin) -> str:
    """Summarize an origin on one line.

    Returns:
        A short description naming the kind of installation.
    """
    if origin.kind == "index":
        return "package index (no direct_url.json)"
    if origin.kind == "unknown":
        return f"unknown ({origin.reason or 'unreadable direct_url.json'})"
    describe = {"vcs": _vcs, "archive": _archive, "directory": _directory}
    return describe[origin.kind](origin) + _subdirectory(origin)


def _installer(installation: Installation) -> str:
    name = installation.installer or "unknown"
    return f"{name} (requested)" if installation.requested else name


def _files(installation: Installation) -> str:
    if installation.record_source is None:
        return "no RECORD; file integrity unavailable"
    count = len(installation.files)
    size = decimal(installation.total_size)
    return f"{count} listed in {installation.record_source}, {size} on disk"


def _integrity(installation: Installation) -> str:
    counts = installation.state_counts()
    parts = [
        f"{counts[state]} {state.replace('_', ' ')}"
        for state in FILE_STATES
        if counts[state]
    ]
    return ", ".join(parts) or "-"


def installation_rows(installation: Installation) -> list[tuple[str, str]]:
    """Derive the label/value rows every human format shows.

    Returns:
        Rows in display order; entry points get one row each.
    """
    rows = [
        ("Name", installation.name),
        ("Version", installation.version),
        ("Origin", describe_origin(installation.origin)),
        ("Installer", _installer(installation)),
        ("Imports", ", ".join(installation.import_packages) or "-"),
        ("Entry points", str(len(installation.entry_points))),
    ]
    rows.extend(
        ("", f"{point.group}: {point.name} = {point.value}")
        for point in installation.entry_points
    )
    rows.extend([("Files", _files(installation))])
    if installation.files:
        rows.append(("Integrity", _integrity(installation)))
    return rows


def flagged_files(installation: Installation) -> list[InstalledFile]:
    """Select the files whose state deserves a line of its own.

    Returns:
        Files that are changed, missing, unverifiable, or out of bounds.
    """
    return [file for file in installation.files if file.state in _FLAGGED]


def installation_notes(installation: Installation) -> list[str]:
    """Explain states a reader could otherwise misread.

    Returns:
        Zero or more one-line notes.
    """
    counts = installation.state_counts()
    notes: list[str] = []
    if counts["unchecked"]:
        notes.append("Hashes were not compared; pass --verify to check them.")
    if counts["not_recorded"]:
        notes.append("A file with no recorded hash is unverified, not changed.")
    if counts["out_of_bounds"]:
        notes.append("Paths outside the selected environment were reported, not read.")
    return notes
