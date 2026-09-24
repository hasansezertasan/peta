"""Color resolution and Rich console rendering."""

from __future__ import annotations

import os
import sys
from io import StringIO
from typing import TYPE_CHECKING

from rich.console import Console
from rich.segment import Segment, Segments

if TYPE_CHECKING:
    from rich.console import RenderableType

__all__ = ["inline", "render", "resolve_color", "sanitize_terminal"]

_KEPT_CONTROLS = frozenset({"\n", "\t"})
_FIRST_PRINTABLE = 0x20
_DELETE = 0x7F
_FIRST_NON_CONTROL = 0xA0

_CONTROL_CHARACTERS = {
    code: None
    for code in [*range(_FIRST_PRINTABLE), *range(_DELETE, _FIRST_NON_CONTROL)]
    if chr(code) not in _KEPT_CONTROLS
}
"""Every C0 and C1 control character, mapped to deletion for ``str.translate``."""


def sanitize_terminal(value: str) -> str:
    """Make untrusted text inert when it is written to a terminal.

    Newlines and tabs stay, because the formatters use them; every other C0 or
    C1 control character is dropped, which is what stops ANSI escape and OSC-8
    hyperlink injection from package metadata. Dropping rather than escaping
    them is deliberate: Rich measures a control character as occupying no
    cells, so a visible stand-in would be one cell wider than the space Rich
    reserved and would push a table's border out of line. Nothing is lost that
    a reader needs — the JSON output still carries the original bytes.

    Returns:
        The value with terminal control characters removed.
    """
    return value.translate(_CONTROL_CHARACTERS)


_LINE_BREAKS = str.maketrans("\n\r\t", "   ")


def inline(value: object) -> str:
    """Make one untrusted value safe to place on a line of terminal output.

    :func:`sanitize_terminal` keeps newlines and tabs because formatters build
    their layout from them, so a value inserted into that layout has to give
    up its own: folded to spaces, they can neither start a forged line nor
    shift a column.

    Returns:
        The value on one line, with terminal control characters removed.
    """
    return sanitize_terminal(str(value).translate(_LINE_BREAKS))


def resolve_color(*, no_color: bool) -> bool:
    """Decide whether Rich output should include color.

    Precedence: an explicit ``--no-color`` flag always wins; otherwise the
    ``NO_COLOR`` environment variable (any non-empty value) disables color;
    otherwise color follows whether stdout is a terminal.

    Returns:
        ``True`` if color should be rendered, ``False`` otherwise.
    """
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _hardened(segment: Segment) -> Segment:
    """Make one rendered segment inert, keeping the rest of its style.

    Safe to do after Rich has measured and padded the row: every control
    character this removes is one Rich already counted as occupying no cells,
    so the table's borders stay where Rich put them.

    Any hyperlink is dropped from the style too. peta never links anything
    itself, and some renderables parse markup whatever the console says —
    ``Panel`` runs ``Text.from_markup`` on a string title — so a package named
    ``[link=https://...]safe[/link]`` could otherwise have Rich emit a live
    OSC-8 hyperlink. Dropping links here closes that for every renderable,
    including ones added later.

    Returns:
        The segment with its text made safe and no hyperlink.
    """
    style = segment.style
    if style is not None and style.link:
        style = style.update_link(None)
    return Segment(sanitize_terminal(segment.text), style, segment.control)


def render(renderable: RenderableType, *, color: bool, width: int = 100) -> str:
    """Render a Rich renderable to a string, with or without ANSI color.

    Rendering happens in two steps so that untrusted metadata can be made
    inert *after* Rich has laid it out but *before* Rich turns styles into
    escape sequences. Sanitizing the finished string instead would have to
    tell peta's own color codes from an attacker's, which it cannot; sanitizing
    every renderer's inputs instead would leave each new call site free to
    forget.

    Markup and emoji substitution are disabled because both let metadata
    change which characters are printed: a ``[bold]`` or a ``:pile_of_poo:``
    in a package summary is data, not an instruction. Highlighting stays on —
    it only colors what is already there, and peta's output has always had it.

    Returns:
        The rendered text: ANSI-colored when ``color`` is ``True``, plain
        otherwise. Has no trailing newline; callers (e.g. ``typer.echo``)
        supply exactly one.
    """
    buf = StringIO()
    console = Console(
        file=buf,
        force_terminal=color,
        no_color=not color,
        width=width,
        markup=False,
        emoji=False,
    )
    laid_out = console.render(renderable, console.options)
    console.print(Segments([_hardened(segment) for segment in laid_out]), end="")
    return buf.getvalue()
