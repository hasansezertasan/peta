"""Unit tests for :mod:`peta.cli.output.console`."""

import pytest
from rich.text import Text

from peta.cli.output.console import render, resolve_color, sanitize_terminal

pytestmark = pytest.mark.unit

ANSI_INJECTION = "name\x1b[31mred\x1b]8;;https://attacker.invalid\x07link\x1b]8;;\x07"
"""Metadata that repaints the terminal and hides a link behind other text."""


def test_terminal_sanitizer_drops_ansi_and_hyperlink_sequences() -> None:
    assert sanitize_terminal(ANSI_INJECTION) == (
        "name[31mred]8;;https://attacker.invalidlink]8;;"
    )


def test_terminal_sanitizer_keeps_the_whitespace_formatters_rely_on() -> None:
    assert sanitize_terminal("a\nb\tc") == "a\nb\tc"


def test_terminal_sanitizer_drops_c1_control_characters() -> None:
    # A bare 0x9b is CSI, so it opens an escape sequence without an ESC byte.
    assert sanitize_terminal("a\x9b31mb\u00a0c") == "a31mb\u00a0c"


class TestResolveColor:
    def test_no_color_flag_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert resolve_color(no_color=True) is False

    def test_no_color_env_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert resolve_color(no_color=False) is False

    def test_no_color_env_empty_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert resolve_color(no_color=False) is True

    def test_tty_enables_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert resolve_color(no_color=False) is True

    def test_non_tty_disables_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)
        assert resolve_color(no_color=False) is False


class TestRender:
    def test_color_true_contains_escape(self) -> None:
        out = render(Text("hi", style="bold red"), color=True)
        assert "\x1b" in out

    def test_color_false_has_no_escape(self) -> None:
        out = render(Text("hi", style="bold red"), color=False)
        assert "\x1b" not in out
        assert "hi" in out

    @pytest.mark.parametrize("color", [True, False])
    def test_untrusted_escape_sequences_never_reach_the_terminal(
        self, *, color: bool
    ) -> None:
        out = render(Text(ANSI_INJECTION), color=color)

        assert "\x1b[31m" not in out
        assert "\x1b]8;;" not in out
        assert "attacker.invalid" in out

    @pytest.mark.parametrize("color", [True, False])
    def test_markup_in_metadata_is_data_not_style(self, *, color: bool) -> None:
        out = render(Text("summary [bold]not bold[/bold]"), color=color)

        assert "[bold]not bold[/bold]" in out

    def test_a_declared_url_is_rendered_as_declared(self) -> None:
        # Rendering does not redact: a query string a package declared is
        # part of the metadata peta exists to report, and peta's own
        # credentials are stripped where diagnostics are built instead.
        text = Text("see https://example.invalid/?key=install now")

        out = render(text, color=False)

        assert "https://example.invalid/?key=install" in out
