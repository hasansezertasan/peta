"""Unit tests for the metadata and file probes behind ``peta origin``."""

from __future__ import annotations

import os
import sys
from importlib.metadata import Distribution, PathDistribution
from typing import TYPE_CHECKING, NoReturn
from unittest.mock import MagicMock

import pytest

from peta.core import installation
from peta.core.installation import _probe, _read_text

if TYPE_CHECKING:
    from os import PathLike
    from pathlib import Path

pytestmark = pytest.mark.unit


class _Custom(Distribution):
    """A distribution that is not a ``PathDistribution``."""

    def __init__(self, text: str | None, *, undecodable: bool = False) -> None:
        self.text = text
        self.undecodable = undecodable

    def read_text(self, filename: str) -> str | None:
        del filename
        if self.undecodable:
            msg = "utf-8"
            raise UnicodeDecodeError(msg, b"\xff", 0, 1, "invalid start byte")
        return self.text

    def locate_file(self, path: str | PathLike[str]) -> NoReturn:
        raise NotImplementedError(path)


def _folder(error: Exception) -> MagicMock:
    folder = MagicMock()
    entry = folder.joinpath.return_value
    entry.open.side_effect = error
    entry.read_bytes.side_effect = error
    return folder


def test_other_distributions_use_their_own_reader() -> None:
    assert _read_text(_Custom("pip\n"), "INSTALLER") == "pip\n"
    assert _read_text(_Custom(None), "INSTALLER") is None


def test_undecodable_file_elsewhere_is_present_but_empty() -> None:
    """Present-but-unreadable must not read as absent: that would claim index."""
    text = _read_text(_Custom(None, undecodable=True), "direct_url.json")
    assert text is not None
    assert not text


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        pytest.param(FileNotFoundError(), None, id="absent"),
        pytest.param(PermissionError(), "", id="unreadable"),
    ],
)
def test_path_distribution_read_failures(
    error: Exception, expected: str | None
) -> None:
    dist = PathDistribution(_folder(error))
    assert _read_text(dist, "INSTALLER") == expected


@pytest.mark.parametrize(
    ("error", "state"),
    [
        pytest.param(FileNotFoundError(), "missing", id="absent"),
        pytest.param(NotADirectoryError(), "unverifiable", id="not-a-directory"),
        pytest.param(PermissionError(), "unverifiable", id="denied"),
        pytest.param(ValueError("embedded null byte"), "unverifiable", id="nul"),
    ],
)
def test_probe_tells_absence_from_inaccessibility(
    error: Exception, state: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "peta.core.installation._open_within", MagicMock(side_effect=error)
    )
    assert _probe(tmp_path, tmp_path / "x") == state


def test_probe_regular_file(tmp_path: Path) -> None:
    root, target = _rooted_file(tmp_path)
    assert isinstance(_probe(root, target), os.stat_result)


@pytest.mark.skipif(  # pragma: no cover
    sys.platform == "win32", reason="needs named pipes"
)
def test_probe_fifo_does_not_block(tmp_path: Path) -> None:
    assert sys.platform != "win32"
    root = tmp_path / "root"
    root.mkdir()
    fifo = root / "pipe"
    os.mkfifo(fifo)
    assert _probe(root, fifo) == "missing"


def _rooted_file(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "mod.py"
    _ = target.write_bytes(b"x")
    return root, target


def test_open_then_locate_accepts_a_handle_inside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where no walk is possible, the handle is asked where it really is."""
    root, target = _rooted_file(tmp_path)
    monkeypatch.setattr(installation, "_final_path", lambda _: target)
    os.close(installation._open_then_locate(root, target))


@pytest.mark.parametrize("located", ["elsewhere.py", None], ids=["outside", "unknown"])
def test_open_then_locate_refuses_a_handle_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, located: str | None
) -> None:
    root, target = _rooted_file(tmp_path)
    final = None if located is None else tmp_path / located
    monkeypatch.setattr(installation, "_final_path", lambda _: final)
    with pytest.raises(OSError, match="led outside"):
        os.close(installation._open_then_locate(root, target))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("C:/path/to/pkg", True),
        (r"C:\path\to\pkg", True),
        ("c:/pkg", True),
        ("x://example.com/repo", False),
        ("x:///path", False),
        ("https://example.com", False),
        ("file:///path", False),
    ],
)
def test_is_drive_path(url: str, *, expected: bool) -> None:
    assert installation.is_drive_path(url) is expected


@pytest.mark.parametrize(
    ("scheme", "expected"),
    [
        ("file", True),
        ("git+file", True),
        ("", True),
        ("http", False),
        ("https", False),
        ("x", False),
    ],
)
def test_is_local_scheme(scheme: str, *, expected: bool) -> None:
    assert installation.is_local_scheme(scheme) is expected


@pytest.mark.parametrize(
    ("url", "malformed"),
    [
        ("x://example.com/repo", False),
        ("x:///repo", True),
        ("C:/repo", False),
        ("C:///repo", True),
        ("https://example.com", False),
        ("https://", True),
        ("file:///local/path", False),
    ],
)
def test_malformed_authority(url: str, *, malformed: bool) -> None:
    assert installation._malformed_authority(url) is malformed
