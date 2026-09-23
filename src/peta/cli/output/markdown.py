"""Markdown output formatters."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, cast

from peta.cli.output.console import inline
from peta.cli.output.summary import (
    file_flags,
    file_publishers,
    file_size,
    summary_rows,
    verdict,
)

if TYPE_CHECKING:
    from peta.core.artifacts import ArtifactFile, ReleaseArtifacts
    from peta.core.models import DependencyNode, PackageInfo

__all__ = [
    "format_artifacts",
    "format_banner",
    "format_compare",
    "format_dep_tree",
    "format_files",
    "format_info",
    "format_versions",
    "format_why",
]


_ACTIVE = re.compile(r"([\\`\[\]<|])")
"""The characters that let untrusted text become active Markdown.

``[`` and ``]`` open links and images — ``![x](https://...)`` in a package
name would load a remote image wherever the output is rendered — and ``<``
opens raw HTML and autolinks. A backtick ends a code span early, ``|`` ends a
table cell, and a trailing backslash would escape whatever peta writes next.
Emphasis characters are left alone on purpose: they cannot load anything or
hide text, and escaping them would litter ordinary names like ``my_pkg``.
"""

_BACKTICK_RUN = re.compile(r"`+")

_TABLE_PIPE = re.compile(r"(\\*)\|")
"""A pipe together with the run of backslashes in front of it."""


def _escaped_pipe(match: re.Match[str]) -> str:
    r"""Leave a pipe with an odd number of backslashes in front of it.

    GFM splits table rows before it parses anything inline, reading
    backslashes in pairs, so ``\\|`` — two backslashes — leaves the pipe
    active. A filename carrying ``\\|`` used to become exactly that once one
    backslash was added, splitting the row and the code span with it.

    Returns:
        The pipe, preceded by an odd-length run of backslashes.
    """
    run = match.group(1)
    return f"{run}{'' if len(run) % 2 else chr(92)}|"


def _one_line(value: object) -> str:
    # Terminal-sanitized *before* any escaping or fence sizing, not only
    # afterwards by ``_plain_output``: removing a control character later can
    # join two backtick runs, or a backslash to the character it should not
    # reach, after the Markdown around them was already decided.
    return inline(value)


def _text(value: object) -> str:
    """Render untrusted text as inert inline Markdown.

    Returns:
        The value on one line, with every active character escaped.
    """
    return _ACTIVE.sub(r"\\\1", _one_line(value))


def format_banner(text: str) -> str:
    """Escape a line printed above a Markdown document for inertness.

    Public for the target-environment banner, which the CLI prepends to the
    document rather than building through a formatter here, and which names
    paths that may carry link or image syntax.

    Returns:
        The line as inert inline Markdown.
    """
    return _text(text)


def _code(value: object, *, in_table: bool = False) -> str:
    """Render untrusted text as a code span it cannot break out of.

    The fence is one backtick longer than any run of backticks inside the
    value, which is how CommonMark lets a code span contain them. Inside a
    table a ``|`` still ends the cell even within a code span, so there it is
    escaped too; elsewhere the backslash would be printed literally.

    Returns:
        The value as a code span.
    """
    content = _one_line(value)
    if in_table:
        content = _TABLE_PIPE.sub(_escaped_pipe, content)
    longest = max(
        (match.end() - match.start() for match in _BACKTICK_RUN.finditer(content)),
        default=0,
    )
    fence = "`" * (longest + 1)
    pad = " " if content.startswith("`") or content.endswith("`") else ""
    return f"{fence}{pad}{content}{pad}{fence}"


def _cell(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, list):
        items = cast("list[object]", value)
        return ", ".join(_text(item) for item in items) or "—"
    return _text(value)


def _security_lines(pkg: PackageInfo) -> list[str]:
    lines: list[str] = []
    if pkg.vulnerabilities:
        lines.extend(["", "## Vulnerabilities", ""])
        for vulnerability in pkg.vulnerabilities:
            severity = (
                f" ({_cell(vulnerability.severity)})" if vulnerability.severity else ""
            )
            fixed = ", ".join(_code(version) for version in vulnerability.fixed_in)
            fix_text = fixed or "no known fix"
            description = f"{_cell(vulnerability.summary)} (fix: {fix_text})"
            lines.append(f"- {_code(vulnerability.id)}{severity}: {description}")
    lines.extend(_warning_lines(pkg))
    return lines


def _warning_lines(*packages: PackageInfo) -> list[str]:
    prefixed = len(packages) > 1

    def item(name: str, source: str, reason: str) -> str:
        owner = f"{_code(name)} — " if prefixed else ""
        return f"- {owner}**{_cell(source)}:** {_cell(reason)}"

    warnings = [
        item(pkg.name, failure.source, failure.reason)
        for pkg in packages
        for failure in pkg.enrichment_failures
    ]
    warnings.extend(
        item(pkg.name, conflict.field, conflict.description)
        for pkg in packages
        for conflict in pkg.enrichment_conflicts
    )
    warnings.extend(
        item(pkg.name, w.source, w.message)
        for pkg in packages
        for w in pkg.provider_warnings
    )
    if not warnings:
        return []
    return ["", "## Enrichment warnings", "", *warnings]


def _vulnerability_count(pkg: PackageInfo) -> str:
    if pkg.vulnerabilities_unknown:
        return "unknown"
    return str(len(pkg.vulnerabilities))


def format_info(pkg: PackageInfo) -> str:
    """Format package metadata as Markdown.

    Returns:
        A Markdown heading and field table.
    """
    rows = [
        ("Source", pkg.source),
        ("Summary", pkg.summary),
        ("License", pkg.license),
        ("Requires Python", pkg.python_requires),
        ("Homepage", pkg.homepage),
        ("Dependencies", pkg.dependencies),
        ("Downloads", pkg.download_count),
        ("Dependents", pkg.dependent_count),
    ]
    lines = [
        f"# {_text(pkg.name)} {_text(pkg.version)}",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    lines.extend(f"| {name} | {_cell(value)} |" for name, value in rows)
    lines.extend(_security_lines(pkg))
    return "\n".join(lines)


def format_compare(a: PackageInfo, b: PackageInfo) -> str:
    """Format a package comparison as Markdown.

    Returns:
        A Markdown comparison table.
    """
    rows = [
        ("Version", a.version, b.version),
        ("Source", a.source, b.source),
        ("License", a.license, b.license),
        ("Requires Python", a.python_requires, b.python_requires),
        ("Dependencies", a.dependencies, b.dependencies),
        ("Vulnerabilities", _vulnerability_count(a), _vulnerability_count(b)),
    ]
    lines = [
        "# Package comparison",
        "",
        f"| Field | {_cell(a.name)} | {_cell(b.name)} |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| {field} | {_cell(a_value)} | {_cell(b_value)} |"
        for field, a_value, b_value in rows
    )
    lines.extend(_warning_lines(a, b))
    return "\n".join(lines)


def _tree_lines(node: DependencyNode, depth: int = 0) -> list[str]:
    suffix = f" {node.version_spec}" if node.version_spec else ""
    state = (
        f" _({node.state.replace('_', ' ')})_"
        if node.state != "satisfied" and node.resolution_failure is None
        else ""
    )
    selected = (
        f" _(selected {_cell(node.selected_version)})_" if node.selected_version else ""
    )
    failure = node.resolution_failure
    unresolved = f" _(unresolved: {_cell(failure.reason)})_" if failure else ""
    lines = [
        f"{'  ' * depth}- {_code(node.name + suffix)}{selected}{state}{unresolved}"
    ]
    for child in node.children:
        lines.extend(_tree_lines(child, depth + 1))
    return lines


def format_dep_tree(node: DependencyNode) -> str:
    """Format a dependency tree as Markdown.

    Returns:
        A heading and nested Markdown list.
    """
    return "\n".join([
        f"# Declared metadata tree for {_text(node.name)}",
        "",
        *_tree_lines(node),
    ])


def format_why(target: str, paths: list[list[str]]) -> str:
    """Format dependency paths as Markdown.

    Returns:
        A heading and one list item per path.
    """
    lines = [f"# Why {_text(target)}?", ""]
    lines.extend(f"- {' → '.join(_code(name) for name in path)}" for path in paths)
    return "\n".join(lines)


def format_files(pkg: PackageInfo) -> str:
    """Format an installed file list as Markdown.

    Returns:
        A heading and Markdown list.
    """
    lines = [f"# Files for {_text(pkg.name)} {_text(pkg.version)}", ""]
    lines.extend(f"- {_code(path)}" for path in pkg.files or [])
    return "\n".join(lines)


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format published versions as Markdown.

    Returns:
        A heading and Markdown table.
    """
    lines = [
        f"# Versions for {_text(name)}",
        "",
        "| Version | Uploaded |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| {_cell(item['version'])} | {_cell(item['upload_time'])} |"
        for item in versions
    )
    return "\n".join(lines)


_ARTIFACT_HEADER = (
    (
        "| File | Kind | Size | Uploaded | Requires | Compatible | SHA-256 | Flags"
        " | Published by |"
    ),
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
)


def _artifact_rows(release: ReleaseArtifacts) -> list[str]:
    """Render the per-file table body.

    Returns:
        One Markdown table row per file.
    """
    return [
        "| "
        + " | ".join([
            _code(file.filename, in_table=True),
            file.kind,
            _cell(file_size(file)),
            _cell(file.upload_time),
            _cell(file.requires_python),
            verdict(file),
            _code(file.sha256, in_table=True) if file.sha256 else "—",
            _cell(file_flags(file)),
            _cell(file_publishers(file)),
        ])
        + " |"
        for file in release.files
    ]


def _yanked_reason(file: ArtifactFile) -> str:
    """Render a yank reason, naming the absence of one explicitly.

    Returns:
        The reason PyPI recorded, or a stand-in when it recorded none.
    """
    return _cell(file.yanked_reason or "no reason given")


def _artifact_notes(release: ReleaseArtifacts) -> list[str]:
    """Report incompatibility reasons, yanks, and failed provenance lookups.

    Returns:
        A trailing Markdown section, empty when there is nothing to report.
    """
    notes = [
        f"- {_code(file.filename)}: {_cell(file.compatibility.reason)}"
        for file in release.files
        if file.compatibility.reason
    ]
    notes.extend(
        f"- {_code(file.filename)} **yanked:** {_yanked_reason(file)}"
        for file in release.files
        if file.yanked
    )
    notes.extend(
        f"- **provenance lookup failed:** {_cell(failure.description)}"
        for failure in release.publisher_failures
    )
    if not notes:
        return []
    return ["", "## Notes", "", *notes]


def format_artifacts(release: ReleaseArtifacts, *, detailed: bool = False) -> str:
    """Format a release's artifacts as Markdown.

    Returns:
        A summary table, an optional per-file table, and any notes.
    """
    lines = [
        f"# Artifacts for {_text(release.name)} {_text(release.version)}",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| {label} | {_cell(value)} |" for label, value in summary_rows(release)
    )
    if detailed and release.files:
        lines.extend(["", "## Files", "", *_ARTIFACT_HEADER, *_artifact_rows(release)])
    lines.extend(_artifact_notes(release))
    return "\n".join(lines)
