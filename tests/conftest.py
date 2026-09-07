"""Shared test configuration for the peta suite."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import cache, http
from tests.transport import FakeTransport

if TYPE_CHECKING:
    from collections.abc import Iterator


_SESSION_CACHE = Path(tempfile.gettempdir()) / "peta-test-cache"
"""Where any cache a test provokes is allowed to land.

One fixed directory rather than a fresh ``mkdtemp`` per test, so the suite
does not litter hundreds of temporary trees; it is emptied between tests
instead.
"""


def _quarantine_cache() -> None:
    """Empty the cache and switch it off, pointing it away from the real one.

    Three protections, because each covers a different way a test could
    otherwise be affected by the cache.

    ``PETA_CACHE_DIR`` redirects the platform default, so even a test that
    invokes the CLI — which configures the cache itself, enabled — cannot
    touch the developer's real ``~/.cache/peta``.

    Emptying the directory stops one test's canned reply from being served to
    the next, which would quietly turn a test of a failure path into a cache
    hit and pass for the wrong reason.

    Disabling it keeps the default behaviour of a plain unit test free of
    disk I/O; tests that mean to exercise the cache opt in via ``cache_dir``.
    """
    shutil.rmtree(_SESSION_CACHE, ignore_errors=True)
    os.environ["PETA_CACHE_DIR"] = str(_SESSION_CACHE)
    cache.configure(directory=_SESSION_CACHE, enabled=False)


def pytest_configure() -> None:
    """Fix the ambient state the suite must not depend on.

    ``LIBRARIES_IO_API_KEY`` is popped because a developer's exported key
    changes the recorded source state from ``unavailable`` to ``empty``, so
    tests would pass or fail based on the environment. Tests that need a key
    patch ``stats.libraries_io_api_key`` directly.
    """
    os.environ.pop("LIBRARIES_IO_API_KEY", None)
    _quarantine_cache()


def pytest_runtest_setup() -> None:
    """Re-quarantine the cache before every test.

    A hook rather than an autouse fixture, which this project's lint rules
    reject. Per-test rather than per-session because a test that invokes the
    CLI reconfigures the cache and enables it, so one-time setup would let
    entries written by one test be read by the next.
    """
    _quarantine_cache()


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


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Enable the cache in a directory private to this test.

    Returns:
        The active cache directory.
    """
    directory = tmp_path / "cache"
    cache.configure(directory=directory, enabled=True)
    return directory


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Drive cache expiry from a clock the test controls.

    Expiry is the whole point of a TTL, and sleeping through one is not a
    test. The returned single-element list is the current time; assign to
    element ``0`` to move it.

    Returns:
        A mutable one-element list holding the current fake timestamp.
    """
    clock = [1_000_000.0]
    monkeypatch.setattr(cache, "now", lambda: clock[0])
    return clock
