"""Color resolution and Rich console rendering."""

from __future__ import annotations

import os
import sys
from io import StringIO

from rich.console import Console

__all__ = ["render", "resolve_color"]


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


def render(renderable: object, *, color: bool, width: int = 100) -> str:
    """Render a Rich renderable to a string, with or without ANSI color.

    Returns:
        The rendered text: ANSI-colored when ``color`` is ``True``, plain
        otherwise.
    """
    buf = StringIO()
    console = Console(file=buf, force_terminal=color, no_color=not color, width=width)
    console.print(renderable)
    return buf.getvalue()
