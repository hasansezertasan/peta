"""Output-format selection and fatal error rendering."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, NoReturn

import typer

from peta.cli.output.json import format_error

if TYPE_CHECKING:
    from peta.core.output import CommandName, MessageCode

__all__ = ["OutputFormat", "fail", "resolve_or_fail", "resolve_output_format"]


class OutputFormat(StrEnum):
    """Supported CLI output representations."""

    RICH = "rich"
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"


def resolve_output_format(
    output_format: OutputFormat | None, *, use_json: bool
) -> OutputFormat:
    """Resolve the deprecated JSON flag against the unified format option.

    ``output_format`` is ``None`` when ``--format`` was left at its default, so
    ``--json`` alone selects JSON while any explicit non-JSON ``--format``
    conflicts with it.

    Returns:
        The selected output format.

    Raises:
        BadParameter: If ``--json`` conflicts with an explicit non-JSON format.
    """
    if not use_json:
        return output_format or OutputFormat.RICH
    if output_format not in {None, OutputFormat.JSON}:
        msg = "--json cannot be combined with a non-JSON --format value"
        raise typer.BadParameter(msg)
    return OutputFormat.JSON


def resolve_or_fail(
    command: CommandName,
    arguments: dict[str, object],
    output_format: OutputFormat | None,
    *,
    use_json: bool,
) -> OutputFormat:
    """Resolve output selection, using a JSON envelope for JSON conflicts.

    Returns:
        The selected output format.
    """
    try:
        return resolve_output_format(output_format, use_json=use_json)
    except typer.BadParameter as exc:
        selected = (
            OutputFormat.JSON if use_json else (output_format or OutputFormat.RICH)
        )
        fail(
            command,
            arguments=arguments,
            code="invalid_arguments",
            message=str(exc),
            output_format=selected,
            exit_code=2,
        )


def fail(
    command: CommandName,
    *,
    arguments: dict[str, object],
    code: MessageCode,
    message: str,
    output_format: OutputFormat,
    exit_code: int,
    source: str | None = None,
) -> NoReturn:
    """Render a fatal error consistently and exit.

    Raises:
        Exit: Always, using ``exit_code``.
    """
    rendered = (
        format_error(
            command, arguments=arguments, code=code, message=message, source=source
        )
        if output_format == OutputFormat.JSON
        else message
    )
    typer.echo(rendered, err=True)
    raise typer.Exit(code=exit_code)
