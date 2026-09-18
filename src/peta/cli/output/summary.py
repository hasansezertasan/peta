"""Format-agnostic derivations shared by the human artifact renderers.

The Rich, text, and Markdown views of a release differ in how they draw a
table, not in what the release says about itself. Keeping the summary rows and
the per-file verdicts here means one release cannot summarize differently
depending on which ``--format`` was asked for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.filesize import decimal

if TYPE_CHECKING:
    from peta.core.artifacts import ArtifactFile, ReleaseArtifacts

__all__ = ["file_flags", "file_publishers", "file_size", "summary_rows", "verdict"]


def verdict(file: ArtifactFile) -> str:
    """Name a file's compatibility verdict in one word.

    ``unknown`` is deliberately distinct from ``no``: peta could not read the
    evidence, which is not the same as having read it and ruled the file out.

    Returns:
        ``"yes"``, ``"no"``, or ``"unknown"``.
    """
    if file.compatibility.compatible is None:
        return "unknown"
    return "yes" if file.compatibility.compatible else "no"


def file_flags(file: ArtifactFile) -> str:
    """List a file's noteworthy states as short markers.

    Returns:
        A comma-joined marker list, or ``"-"`` when the file has none.
    """
    markers = [
        marker
        for marker, present in (
            ("yanked", file.yanked),
            ("metadata", file.core_metadata),
            ("provenance", file.provenance_url is not None),
        )
        if present
    ]
    return ", ".join(markers) or "-"


def file_size(file: ArtifactFile) -> str:
    """Render one file's size for human output.

    Returns:
        A human-readable size, or ``"-"`` when the index reported none.
    """
    if file.size is None:
        return "-"
    return decimal(file.size)


def file_publishers(file: ArtifactFile) -> str:
    """Name every Trusted Publisher recorded for one file.

    Returns:
        The publishers, or ``"-"`` when none was supplied.
    """
    return "; ".join(p.description for p in file.publishers) or "-"


def _compatible_value(release: ReleaseArtifacts) -> str:
    """State how many files fit, keeping unestablished verdicts visible.

    A file peta could not judge belongs in neither the numerator nor silence:
    counting it only in the denominator reads as "ruled out", which is the
    answer the unknown verdict exists to avoid giving.

    Returns:
        The compatible count, with any unknown verdicts named.
    """
    unknown = sum(f.compatibility.compatible is None for f in release.files)
    value = f"{len(release.compatible)} of {len(release.files)}"
    return f"{value} ({unknown} unknown)" if unknown else value


def _size_value(release: ReleaseArtifacts) -> str:
    """Report the aggregate size without implying a missing one is zero.

    Returns:
        The total, qualified when the index did not size every file.
    """
    total = decimal(release.total_size)
    if all(f.size is not None for f in release.files):
        return total
    return f"at least {total}"


def _yanked_value(release: ReleaseArtifacts) -> str:
    """Describe the release's yank state, including a partial one.

    Returns:
        Whether the whole release, some of it, or none of it is yanked.
    """
    yanked = sum(f.yanked for f in release.files)
    if not yanked:
        return "no"
    if yanked == len(release.files):
        return "entire release"
    return f"{yanked} of {len(release.files)} files"


def summary_rows(release: ReleaseArtifacts) -> list[tuple[str, str]]:
    """Build the labeled release summary every human renderer shows.

    Returns:
        Label/value pairs, in display order.
    """
    total = len(release.files)
    requires = sorted({f.requires_python for f in release.files if f.requires_python})
    rows = [
        ("Files", str(total)),
        ("Wheels", str(len(release.wheels))),
        ("Sdists", str(len(release.sdists))),
        (f"Compatible (Python {release.target.version})", _compatible_value(release)),
        ("Total size", _size_value(release)),
        ("Requires-Python", ", ".join(requires) or "-"),
        ("Provenance", f"{len(release.with_provenance)} of {total} files"),
        ("Yanked", _yanked_value(release)),
    ]
    if release.publishers:
        rows.append(("Published by", "; ".join(release.publishers)))
    return rows
