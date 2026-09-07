"""E2E: full CLI against real PyPI. Opt-in (network).

Skipped unless PETA_E2E_NETWORK=1 is set. Run with:
``PETA_E2E_NETWORK=1 uv run pytest -m e2e``.
"""

import json
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


def _assert_count_or_reported_failure(data: dict, source: str, field: str) -> None:
    """Check a best-effort count, accepting a failure the envelope owns up to.

    These sources are optional and rate-limit public callers, so a count is
    not guaranteed. What is guaranteed is coherence: either the source
    succeeded and the count is a positive integer, or it did not and the
    envelope accounts for the gap — a null count and a warning naming the
    source — instead of quietly reporting success.
    """
    states = {item["name"]: item["state"] for item in data["sources"]}
    assert source in states, f"{source} missing from {states}"
    if states[source] != "success":
        assert data["result"][field] is None
        assert any(item["source"] == source for item in data["warnings"])
        return
    assert isinstance(data["result"][field], int)
    assert data["result"][field] > 0


def test_info_remote_download_count() -> None:
    result = runner.invoke(app, ["info", "requests", "--remote", "--json"])
    assert result.exit_code == 0
    _assert_count_or_reported_failure(
        json.loads(result.output), "pypistats", "download_count"
    )


@pytest.mark.skipif(
    not os.environ.get("LIBRARIES_IO_API_KEY"),
    reason="dependent count requires LIBRARIES_IO_API_KEY",
)
def test_info_remote_dependent_count() -> None:
    result = runner.invoke(app, ["info", "requests", "--remote", "--json"])
    assert result.exit_code == 0
    _assert_count_or_reported_failure(
        json.loads(result.output), "libraries.io", "dependent_count"
    )
