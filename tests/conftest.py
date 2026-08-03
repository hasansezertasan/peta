"""Shared fixtures for peta tests."""

from __future__ import annotations

import pytest

from peta.core.models import PackageInfo


@pytest.fixture
def make_package():  # noqa: ANN201
    def _make(**overrides: object) -> PackageInfo:
        base: dict[str, object] = {
            "name": "requests",
            "version": "2.31.0",
            "source": "local",
            "summary": "Python HTTP for Humans.",
            "dependencies": ["urllib3"],
            "files": None,
            "vulnerabilities": [],
        }
        base.update(overrides)
        return PackageInfo(**base)  # type: ignore[arg-type]

    return _make
