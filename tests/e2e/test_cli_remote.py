"""E2E: full CLI against real PyPI. Opt-in (network).

Skipped unless PETA_E2E_NETWORK=1 is set. Run with:
``PETA_E2E_NETWORK=1 uv run pytest -m e2e``.
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


def test_info_remote_osv_enrichment() -> None:
    # ``jinja2`` has real, long-standing OSV/PyPI advisories, so this exercises
    # a live OSV lookup and merge without depending on ephemeral CVE data.
    result = runner.invoke(app, ["info", "jinja2==2.4.1", "--remote"])
    assert result.exit_code == 0
    assert "vulnerabilities" in result.output.lower()
