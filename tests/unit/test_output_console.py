"""Unit tests for :mod:`peta.output.console`."""

import pytest

from peta.output.console import render, resolve_color

pytestmark = pytest.mark.unit


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
        out = render("[bold red]hi[/bold red]", color=True)
        assert "\x1b" in out

    def test_color_false_has_no_escape(self) -> None:
        out = render("[bold red]hi[/bold red]", color=False)
        assert "\x1b" not in out
        assert "hi" in out
