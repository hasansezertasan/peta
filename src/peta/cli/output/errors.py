"""Application-boundary formatting for parser validation failures."""

from __future__ import annotations

import sys
from itertools import pairwise
from typing import TYPE_CHECKING, TypeGuard, cast, override

import typer
from typer.core import TyperGroup
from typer.exceptions import TyperException

from peta.cli.output.json import format_error

if TYPE_CHECKING:
    from collections.abc import Sequence

    from peta.core.output import CommandName

__all__ = ["StructuredErrorGroup"]

_COMMANDS: frozenset[CommandName] = frozenset({
    "info",
    "compare",
    "deps",
    "files",
    "versions",
})


def _json_requested(args: list[str]) -> bool:
    if "--json" in args or any(
        arg.startswith("--format=") and arg.partition("=")[2].casefold() == "json"
        for arg in args
    ):
        return True
    return any(
        option == "--format" and value.casefold() == "json"
        for option, value in pairwise(args)
    )


def _command(args: list[str]) -> CommandName:
    for arg in args:
        if _is_command(arg):
            return arg
    return "info"


def _is_command(value: str) -> TypeGuard[CommandName]:
    return value in _COMMANDS


class StructuredErrorGroup(TyperGroup):
    """Typer group that preserves the JSON contract for parser errors."""

    @override
    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: object,
    ) -> object:
        """Run the CLI and envelope pre-handler failures when JSON was requested.

        Returns:
            The command callback result when standalone mode is disabled.

        Raises:
            SystemExit: When a standalone JSON invocation exits.
            TyperException: When validation fails outside standalone mode.
        """
        raw_args = list(sys.argv[1:] if args is None else args)
        if not _json_requested(raw_args):
            return cast(
                "object",
                super().main(
                    args=args,
                    prog_name=prog_name,
                    complete_var=complete_var,
                    standalone_mode=standalone_mode,
                    windows_expand_args=windows_expand_args,
                    **extra,
                ),
            )
        try:
            result = cast(
                "object",
                super().main(
                    args=args,
                    prog_name=prog_name,
                    complete_var=complete_var,
                    standalone_mode=False,
                    windows_expand_args=windows_expand_args,
                    **extra,
                ),
            )
        except TyperException as exc:
            rendered = format_error(
                _command(raw_args),
                arguments={"argv": raw_args},
                code="invalid_arguments",
                message=exc.format_message(),
            )
            typer.echo(rendered, err=True)
            if standalone_mode:
                raise SystemExit(exc.exit_code) from exc
            raise
        if standalone_mode and isinstance(result, int):
            raise SystemExit(result)
        return result
