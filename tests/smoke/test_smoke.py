"""Smoke tests: import and entry point resolve."""

import pytest
from typer.testing import CliRunner

import peta
from peta.cli.app import app

pytestmark = pytest.mark.smoke
runner = CliRunner()


def test_version_attribute() -> None:
    assert isinstance(peta.__version__, str)
    assert peta.__version__


def test_version_command() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("peta ")
