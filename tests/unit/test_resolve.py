"""Unit tests for shared package resolution (core layer mocked)."""

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest
import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import PackageInfo
from peta.core.resolve import parse_package_arg, resolve_package

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(name="requests", version="2.31.0", source="local")
    return replace(base, **over)


class TestParsePackageArg:
    def test_name_only(self) -> None:
        assert parse_package_arg("requests") == ("requests", None)

    def test_name_and_version(self) -> None:
        assert parse_package_arg("requests==2.28.0") == ("requests", "2.28.0")

    def test_strips_whitespace(self) -> None:
        assert parse_package_arg(" requests == 2.28.0 ") == ("requests", "2.28.0")


class TestResolvePackage:
    @patch("peta.core.resolve.local_get_package")
    def test_local_first(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        pkg = resolve_package("requests", local=False, remote=False)
        assert pkg.name == "requests"
        ml.assert_called_once_with("requests")

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        pkg = resolve_package("x", local=False, remote=False)
        assert pkg.source == "remote"

    @patch("peta.core.resolve.remote_get_package")
    def test_version_specifier_queries_remote(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(version="2.28.0", source="remote")
        resolve_package("requests==2.28.0", local=False, remote=False)
        mr.assert_called_once_with("requests", "2.28.0")

    @patch("peta.core.resolve.remote_get_package")
    def test_remote_flag_forces_remote(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        resolve_package("requests", local=False, remote=True)
        mr.assert_called_once_with("requests")

    @patch("peta.core.resolve.local_get_package")
    def test_local_flag_forces_local(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        resolve_package("requests", local=True, remote=False)
        ml.assert_called_once_with("requests")

    @patch("peta.core.resolve.remote_get_package")
    def test_local_with_version_rejected(self, mr: MagicMock) -> None:
        with pytest.raises(typer.BadParameter):
            resolve_package("requests==2.28.0", local=True, remote=False)
        mr.assert_not_called()
