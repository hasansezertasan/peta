"""Integration: resolve -> render wired together, HTTP served from canned replies."""

import json
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

if TYPE_CHECKING:
    from tests.transport import FakeTransport

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


def _serve_all_sources(fake_http: FakeTransport) -> None:
    """Answer every source ``info`` consults, so no request escapes to the network.

    The enrichment sources are registered too, not just PyPI: they are
    optional, so an unanswered request would be swallowed as a provider
    failure and the test would still pass while quietly reaching out.
    """
    fake_http.reply(url="pypi.org", json=_PAYLOAD)
    fake_http.reply(url="api.osv.dev", json={"vulns": []})
    fake_http.reply(url="pypistats.org", json={"data": {"last_month": 5}})


def test_remote_info_renders(fake_http: FakeTransport) -> None:
    _serve_all_sources(fake_http)
    result = runner.invoke(app, ["info", "flask", "--remote"])
    assert result.exit_code == 0
    assert "flask" in result.output
    assert "3.0.0" in result.output


def test_remote_info_json(fake_http: FakeTransport) -> None:
    _serve_all_sources(fake_http)
    result = runner.invoke(app, ["info", "flask", "--remote", "--json"])
    assert json.loads(result.output)["result"]["name"] == "flask"
