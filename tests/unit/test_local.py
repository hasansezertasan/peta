"""Unit tests for the local metadata fetcher (importlib.metadata mocked)."""

from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from peta.core.local import PackageNotFoundError, get_package

pytestmark = pytest.mark.unit


def _msg(**headers: str) -> Message:
    msg = Message()
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    return msg


@patch("peta.core.local.importlib_metadata")
def test_minimal_missing_optionals(mock_meta: MagicMock) -> None:
    dist = MagicMock()
    dist.metadata = _msg(Name="minimal-pkg", Version="1.0.0")
    dist.requires = None
    dist.files = None
    mock_meta.distribution.return_value = dist

    result = get_package("minimal-pkg")
    assert result.name == "minimal-pkg"
    assert result.version == "1.0.0"
    assert result.source == "local"
    assert result.author is None
    assert result.dependencies == []
    assert result.files is None


@patch("peta.core.local.importlib_metadata")
def test_parses_urls_keywords_deps_files(mock_meta: MagicMock) -> None:
    md = _msg(Name="rich", Version="13.0.0", Summary="pretty", Keywords="cli, tui")
    md["Project-URL"] = "Source, https://github.com/Textualize/rich"
    md["Classifier"] = "Programming Language :: Python :: 3"
    dist = MagicMock()
    dist.metadata = md
    dist.requires = ["pygments>=2.6"]
    dist.files = ["rich/__init__.py", "rich/console.py"]
    mock_meta.distribution.return_value = dist

    result = get_package("rich")
    assert result.project_urls == {"Source": "https://github.com/Textualize/rich"}
    assert result.keywords == ["cli", "tui"]
    assert result.dependencies == ["pygments>=2.6"]
    assert result.files == ["rich/__init__.py", "rich/console.py"]
    assert result.classifiers == ["Programming Language :: Python :: 3"]


@patch("peta.core.local.importlib_metadata")
def test_not_found_raises(mock_meta: MagicMock) -> None:
    import importlib.metadata as real

    mock_meta.PackageNotFoundError = real.PackageNotFoundError
    mock_meta.distribution.side_effect = real.PackageNotFoundError("x")
    with pytest.raises(PackageNotFoundError):
        get_package("nope-xyz")
