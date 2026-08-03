"""E2E: full CLI against real PyPI. Opt-in (network).

Run with: uv run pytest -m e2e_remote  (deselected by default).
"""

import os

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("PETA_E2E_NETWORK") != "1",
        reason="network e2e disabled; set PETA_E2E_NETWORK=1 to run",
    ),
]
runner = CliRunner()


def test_versions_httpx_remote() -> None:
    result = runner.invoke(app, ["versions", "httpx", "-n", "5"])
    assert result.exit_code == 0
    assert "httpx" in result.output.lower()


def test_info_remote_requests() -> None:
    result = runner.invoke(app, ["info", "requests", "--remote"])
    assert result.exit_code == 0
    assert "requests" in result.output.lower()
