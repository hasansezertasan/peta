"""Smoke tests: import and entry point resolve."""

import importlib

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = pytest.mark.smoke
runner = CliRunner()


def test_package_imports() -> None:
    assert importlib.import_module("peta") is not None


def test_version_command() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("peta ")
