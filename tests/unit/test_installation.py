"""Unit tests for the metadata and file probes behind ``peta origin``."""

from __future__ import annotations

from importlib.metadata import Distribution, PathDistribution
from typing import TYPE_CHECKING, NoReturn
from unittest.mock import MagicMock

import pytest

from peta.core.installation import _probe, _read_text

if TYPE_CHECKING:
    from os import PathLike

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
        pytest.param(PermissionError(), "unverifiable", id="denied"),
        pytest.param(ValueError("embedded null byte"), "unverifiable", id="nul"),
    ],
)
def test_probe_tells_absence_from_inaccessibility(error: Exception, state: str) -> None:
    located = MagicMock()
    located.stat.side_effect = error
    assert _probe(located) == state
