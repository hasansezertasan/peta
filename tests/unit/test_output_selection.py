"""Unit tests for output selection."""

import pytest
import typer

from peta.cli.output.selection import OutputFormat, fail, resolve_output_format

pytestmark = pytest.mark.unit


def test_selected_format_is_preserved() -> None:
    assert (
        resolve_output_format(OutputFormat.MARKDOWN, use_json=False)
        == OutputFormat.MARKDOWN
    )


def test_unset_format_defaults_to_rich() -> None:
    assert resolve_output_format(None, use_json=False) == OutputFormat.RICH


def test_json_alias_selects_json() -> None:
    assert resolve_output_format(None, use_json=True) == OutputFormat.JSON


def test_json_alias_accepts_explicit_json() -> None:
    assert resolve_output_format(OutputFormat.JSON, use_json=True) == OutputFormat.JSON


@pytest.mark.parametrize(
    "explicit", [OutputFormat.RICH, OutputFormat.TEXT, OutputFormat.MARKDOWN]
)
def test_json_alias_rejects_conflicting_format(explicit: OutputFormat) -> None:
    with pytest.raises(typer.BadParameter):
        resolve_output_format(explicit, use_json=True)


def test_a_fatal_message_is_printed_on_one_inert_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A malformed index key ends up in a validation error's path, so the
    # message can carry attacker text; it must not add lines or emit escapes.
    message = "malformed response: field $.files[0].hashes.x\nForged: ok\x1b[31m"

    with pytest.raises(typer.Exit):
        fail(
            "info",
            arguments={},
            code="network_error",
            message=message,
            output_format=OutputFormat.TEXT,
            exit_code=2,
        )

    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "\x1b" not in err
    assert "Forged: ok" in err
