"""Unit tests for output selection."""

import pytest
import typer

from peta.cli.output.selection import OutputFormat, resolve_output_format

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
