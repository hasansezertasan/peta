"""E2E: full CLI against locally-installed packages (no network)."""

import json

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = pytest.mark.e2e
runner = CliRunner()


def test_info_local_pkg() -> None:
    result = runner.invoke(app, ["info", "typer", "--local"])
    assert result.exit_code == 0
    assert "typer" in result.output.lower()


def test_files_local_pkg() -> None:
    result = runner.invoke(app, ["files", "rich"])
    assert result.exit_code == 0
    assert ".py" in result.output


def test_info_local_json() -> None:
    result = runner.invoke(app, ["info", "typer", "--local", "--json"])
    assert json.loads(result.output)["source"] == "local"


def test_deps_local_pkg() -> None:
    result = runner.invoke(app, ["deps", "rich", "--local"])
    assert result.exit_code == 0
