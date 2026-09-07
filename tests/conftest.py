"""Shared test configuration for the peta suite."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import http
from tests.transport import FakeTransport

if TYPE_CHECKING:
    from collections.abc import Iterator


def pytest_configure() -> None:
    """Keep Libraries.io unconfigured for the whole session.

    Without this, a developer's exported ``LIBRARIES_IO_API_KEY`` changes the
    recorded source state from ``unavailable`` to ``empty``, so tests pass or
    fail based on the ambient environment. Tests that need a key patch
    ``stats.libraries_io_api_key`` directly.
    """
    os.environ.pop("LIBRARIES_IO_API_KEY", None)


@pytest.fixture
def fake_http(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeTransport]:
    """Serve peta's shared client from a canned, request-recording transport.

    Patches the client accessor rather than the cached client itself, so the
    real pooled instance is never built and no test can reach the network
    through it.

    Yields:
        The transport to register replies on and assert requests against.
    """
    fake = FakeTransport()
    client = httpx.Client(transport=httpx.MockTransport(fake.handle))
    monkeypatch.setattr(http, "client", lambda: client)
    yield fake
    client.close()
