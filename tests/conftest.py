"""Shared test configuration for the peta suite."""

from __future__ import annotations

import os


def pytest_configure() -> None:
    """Keep Libraries.io unconfigured for the whole session.

    Without this, a developer's exported ``LIBRARIES_IO_API_KEY`` changes the
    recorded source state from ``unavailable`` to ``empty``, so tests pass or
    fail based on the ambient environment. Tests that need a key patch
    ``stats.libraries_io_api_key`` directly.
    """
    os.environ.pop("LIBRARIES_IO_API_KEY", None)
