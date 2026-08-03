"""Integration: resolve -> render wired together, httpx boundary mocked."""

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = pytest.mark.integration
runner = CliRunner()

_PAYLOAD = {
    "info": {
        "name": "flask",
        "version": "3.0.0",
        "summary": "web",
        "author": "a",
        "author_email": None,
        "maintainer": None,
        "license": "BSD",
        "requires_python": ">=3.8",
        "home_page": None,
        "project_urls": {},
        "requires_dist": ["werkzeug", "jinja2"],
        "classifiers": [],
        "keywords": "web,wsgi",
    },
    "vulnerabilities": [],
}


@patch("peta.core.remote.httpx")
def test_remote_info_renders(mock_httpx: MagicMock) -> None:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _PAYLOAD
    mock_httpx.get.return_value = resp
    result = runner.invoke(app, ["info", "flask", "--remote"])
    assert result.exit_code == 0
    assert "flask" in result.output
    assert "3.0.0" in result.output


@patch("peta.core.remote.httpx")
def test_remote_info_json(mock_httpx: MagicMock) -> None:
    import json

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _PAYLOAD
    mock_httpx.get.return_value = resp
    result = runner.invoke(app, ["info", "flask", "--remote", "--json"])
    assert json.loads(result.output)["name"] == "flask"
