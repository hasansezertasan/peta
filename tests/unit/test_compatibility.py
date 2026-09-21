"""Unit tests for shared package compatibility checks."""

from unittest.mock import patch

import pytest

from peta.core.compatibility import supports_python
from peta.core.models import PackageInfo

pytestmark = pytest.mark.unit


def test_runtime_prerelease_is_not_treated_as_final() -> None:
    package = PackageInfo(
        name="dep", version="1.0", source="local", python_requires=">=3.15"
    )

    with patch(
        "peta.core.compatibility.platform.python_version", return_value="3.15.0rc1"
    ):
        assert supports_python(package, None) is False
