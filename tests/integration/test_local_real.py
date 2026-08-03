"""Integration: core.local against really-installed distributions."""

import pytest

from peta.core.local import PackageNotFoundError, get_package
from peta.core.models import PackageInfo

pytestmark = pytest.mark.integration


def test_reads_installed_typer() -> None:
    result = get_package("typer")
    assert isinstance(result, PackageInfo)
    assert result.name.lower() == "typer"
    assert result.source == "local"
    assert result.version
    assert result.files is not None


def test_reads_installed_rich_dependencies() -> None:
    result = get_package("rich")
    assert isinstance(result.dependencies, list)


def test_missing_raises() -> None:
    with pytest.raises(PackageNotFoundError):
        get_package("definitely-not-installed-xyz-123")
