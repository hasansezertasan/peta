"""Origin and file-integrity inspection against real metadata directories.

Each fixture lays out a ``site-packages`` directory by hand, the way an
installer would, so every origin kind and every file state is exercised
against real files rather than a mocked ``Distribution``.
"""

from __future__ import annotations

import base64
import gc
import hashlib
import importlib.metadata
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from peta.cli.app import app
from peta.core import installation
from peta.core.installation import inspect_installation
from peta.core.local import LocalTarget, PackageNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from peta.core.installation import FileState, Installation, RecordSource

pytestmark = pytest.mark.integration
runner = CliRunner()

_METADATA = """\
Metadata-Version: 2.1
Name: {name}
Version: 1.0.0
"""


def _record_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _install(
    site: Path,
    name: str,
    *,
    files: dict[str, bytes] | None = None,
    extra_rows: tuple[str, ...] = (),
    metadata_files: dict[str, str] | None = None,
    record: bool = True,
) -> Path:
    """Lay out one installed distribution under ``site``.

    Returns:
        The ``.dist-info`` directory.
    """
    dist_info = site / f"{name}-1.0.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(_METADATA.format(name=name), encoding="utf-8")
    rows: list[str] = []
    for relative, content in (files or {}).items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(content)
        rows.append(f"{relative},{_record_hash(content)},{len(content)}")
    for metadata_name, text in (metadata_files or {}).items():
        (dist_info / metadata_name).write_text(text, encoding="utf-8")
    rows.extend(extra_rows)
    if record:
        rows.append(f"{dist_info.name}/RECORD,,")
        (dist_info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return dist_info


def _inspect(site: Path, name: str, *, verify: bool = False) -> Installation:
    return inspect_installation(
        name, target=LocalTarget.create(None, (str(site),)), verify=verify
    )


def _states(installation: Installation) -> dict[str, FileState]:
    return {file.path: file.state for file in installation.files}


def _posix_only(reason: str) -> pytest.MarkDecorator:
    """Skip on Windows; pair with ``# pragma: no cover`` so its gate holds there.

    Returns:
        The skip marker.
    """
    return pytest.mark.skipif(sys.platform == "win32", reason=reason)


_CORRUPTIBLE = {
    "lzma-stream": (zipfile.ZIP_LZMA, 9),
    "zstd-stream": (getattr(zipfile, "ZIP_ZSTANDARD", zipfile.ZIP_STORED), 4),
}
"""Compressed streams a test corrupts, and the header bytes to leave intact."""


@pytest.fixture
def release_archives(tmp_path: Path) -> Iterator[None]:
    """Close the zip files importlib's path cache keeps open after a test.

    ``importlib.metadata`` memoizes each search path, and a zipped one holds
    its archive open. Left to the garbage collector, the handle can be
    finalized before its ``ZipFile`` in some later test, which then fails on
    the ``ResourceWarning``; closing it here makes the release deterministic.
    """
    yield
    importlib.metadata.MetadataPathFinder.invalidate_caches()
    for obj in gc.get_objects():
        if (
            isinstance(obj, zipfile.ZipFile)
            and obj.filename
            and Path(obj.filename).is_relative_to(tmp_path)
        ):
            obj.close()


@pytest.fixture
def site(tmp_path: Path) -> Path:
    """Return an empty ``site-packages`` inside a would-be environment.

    Returns:
        The directory to install fixtures into.
    """
    root = tmp_path / "env" / "lib" / "site-packages"
    root.mkdir(parents=True)
    return root


class TestOrigin:
    """Each ``direct_url.json`` shape, plus its absence."""

    def test_ordinary_index_install(self, site: Path) -> None:
        _install(
            site,
            "plain",
            files={"plain/__init__.py": b""},
            metadata_files={"INSTALLER": "pip\n", "REQUESTED": ""},
        )
        found = _inspect(site, "plain")
        assert found.origin.kind == "index"
        assert found.installer == "pip"
        assert found.requested is True

    def test_url_fragment_is_dropped(self, site: Path) -> None:
        """A fragment carries nothing PEP 610 keeps there, but can carry a token."""
        direct_url = {
            "url": "https://x.io/r#access_token=s3cret",  # pragma: allowlist secret
            "dir_info": {},
        }
        _install(
            site, "fragpkg", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        assert _inspect(site, "fragpkg").origin.url == "https://x.io/r"

    def test_vcs_install(self, site: Path) -> None:
        direct_url = {
            "url": "https://u:pw@github.com/org/v.git",  # pragma: allowlist secret
            "vcs_info": {
                "vcs": "git",
                "requested_revision": "main",
                "commit_id": "3f2a1c9d0e8b7a6f5e4d3c2b1a0f9e8d7c6b5a49",
            },
        }
        _install(
            site, "vcspkg", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        origin = _inspect(site, "vcspkg").origin
        assert origin.kind == "vcs"
        assert origin.vcs == "git"
        assert origin.requested_revision == "main"
        assert origin.commit_id == direct_url["vcs_info"]["commit_id"]
        # A credential the installer recorded must never be reported.
        assert origin.url == "https://github.com/org/v.git"

    def test_archive_install(self, site: Path) -> None:
        direct_url = {
            "url": "https://example.com/archpkg-1.0.0.tar.gz",
            "archive_info": {"hashes": {"sha256": "ab" * 32}, "hash": "md5=cd"},
        }
        _install(
            site, "archpkg", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        origin = _inspect(site, "archpkg").origin
        assert origin.kind == "archive"
        assert origin.archive_hashes == {"sha256": "ab" * 32, "md5": "cd"}

    def test_legacy_archive_hash_without_an_algorithm_is_ignored(
        self, site: Path
    ) -> None:
        direct_url = {
            "url": "https://example.com/a.tar.gz",
            "archive_info": {"hash": "x"},
        }
        _install(
            site, "oldarch", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        assert _inspect(site, "oldarch").origin.archive_hashes == {}

    def test_editable_install(self, site: Path) -> None:
        direct_url = {
            "url": "file:///home/dev/src/edpkg",
            "dir_info": {"editable": True},
        }
        _install(
            site,
            "edpkg",
            files={"__editable__.edpkg-1.0.0.pth": b"/home/dev/src/edpkg\n"},
            metadata_files={"direct_url.json": json.dumps(direct_url)},
        )
        found = _inspect(site, "edpkg")
        assert found.origin.kind == "directory"
        assert found.origin.editable is True
        assert found.origin.url == "file:///home/dev/src/edpkg"
        # The path hook is an installer helper, not something to import.
        assert found.import_packages == []

    def test_undecodable_metadata_does_not_abort(self, site: Path) -> None:
        dist_info = _install(site, "garbled")
        _ = (dist_info / "direct_url.json").write_bytes(b"\xff\xfe{")
        _ = (dist_info / "INSTALLER").write_bytes(b"pip\xff\n")
        found = _inspect(site, "garbled")
        assert found.origin.kind == "unknown"
        assert found.installer == "pip\ufffd"

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/repo",
            "git+ssh://git@example.com/repo",
            "file:///home/dev/src/pkg",
            "git+file:///home/dev/src/pkg",
            "/home/dev/src/pkg",
            "C:\\Users\\dev\\pkg",
        ],
    )
    def test_well_formed_direct_url_is_kept(self, site: Path, url: str) -> None:
        text = json.dumps({"url": url, "dir_info": {}})
        _install(site, "okpkg", metadata_files={"direct_url.json": text})
        assert _inspect(site, "okpkg").origin.kind == "directory"

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            pytest.param("{not json", "not valid JSON", id="malformed"),
            pytest.param("[]", "not an object", id="not-an-object"),
            pytest.param('{"vcs_info": {}}', "has no url", id="no-url"),
            pytest.param('{"url": "  ", "dir_info": {}}', "has no url", id="blank-url"),
            pytest.param('{"url": "https://x"}', "names no source", id="no-info"),
            pytest.param(
                '{"url": "https://x", "n": ' + "9" * 5000 + "}",
                "not valid JSON",
                id="oversized-int",
            ),
            pytest.param(
                '{"url": "http://a]b/x", "dir_info": {}}',
                "malformed url",
                id="malformed-url",
            ),
            pytest.param(
                r'{"url": "https:\\\\user:secret@example.com\\repo", "dir_info": {}}',
                "malformed url",
                id="backslash-authority",
            ),
            pytest.param(
                '{"url": "https:user:secret@example.com/repo", "dir_info": {}}',
                "malformed url",
                id="missing-authority",
            ),
            pytest.param(
                '{"url": "https://u:s3cret/p", "dir_info": {}}',
                "malformed url",
                id="password-in-port",
            ),
            pytest.param(
                '{"url": "https://u:p@/path", "dir_info": {}}',
                "malformed url",
                id="missing-hostname-userinfo",
            ),
            pytest.param(
                '{"url": "https://:443/path", "dir_info": {}}',
                "malformed url",
                id="missing-hostname-port",
            ),
            pytest.param(
                '{"url": "//example.com/private/repo", "dir_info": {}}',
                "malformed url",
                id="scheme-relative",
            ),
            pytest.param(
                '{"url": "https://example.com/\\ud800", "archive_info": {}}',
                "malformed text",
                id="surrogate-url",
            ),
            pytest.param(
                '{"url": "https://x", "vcs_info": {"commit_id": "\\ud800"}}',
                "malformed text",
                id="surrogate-vcs-field",
            ),
            pytest.param(
                '{"url": "https://x", "archive_info": {"hashes": {"\\udfff": "a"}}}',
                "malformed text",
                id="surrogate-hash-name",
            ),
        ],
    )
    def test_unreadable_direct_url_is_unknown(
        self, site: Path, text: str, reason: str
    ) -> None:
        _install(site, "oddpkg", metadata_files={"direct_url.json": text})
        origin = _inspect(site, "oddpkg").origin
        assert origin.kind == "unknown"
        assert origin.reason is not None
        assert reason in origin.reason


class TestMetadata:
    """Import mappings and entry points."""

    def test_import_packages_are_inferred_from_record(self, site: Path) -> None:
        _install(
            site,
            "multi",
            files={
                "multi/__init__.py": b"",
                "multi_ext.py": b"",
                "multi/__pycache__/x.pyc": b"",
            },
            extra_rows=("../../../bin/multi,,",),
        )
        assert _inspect(site, "multi").import_packages == ["multi", "multi_ext"]

    @pytest.mark.parametrize(
        ("filename", "names"),
        [
            pytest.param("ext.cpython-311-x86_64-linux-gnu.so", ["ext"], id="linux"),
            pytest.param("ext.cp311-win_amd64.pyd", ["ext"], id="windows"),
            pytest.param("ext.cpython-39-darwin.so", ["ext"], id="macos"),
            pytest.param("ext.abi3.so", ["ext"], id="stable-abi"),
            pytest.param("ext.pth", [], id="not-a-module"),
            pytest.param("ext.pyw", ["ext"], id="windowed-source"),
            pytest.param("ext.bar.py", [], id="dotted-source"),
            pytest.param("ext.cpython-311.pyc", [], id="tagged-bytecode"),
        ],
    )
    def test_extension_names_ignore_the_host_abi(
        self, site: Path, filename: str, names: list[str]
    ) -> None:
        """Another interpreter's ABI tag still names the module it builds."""
        _install(site, "native", files={filename: b""})
        assert _inspect(site, "native").import_packages == names

    @pytest.mark.parametrize("declared", ["", "  \n\n"])
    def test_empty_top_level_txt_falls_back_to_record(
        self, site: Path, declared: str
    ) -> None:
        _install(
            site,
            "blank",
            files={"blank/__init__.py": b""},
            metadata_files={"top_level.txt": declared},
        )
        assert _inspect(site, "blank").import_packages == ["blank"]

    @pytest.mark.parametrize(
        ("entries", "separator", "kept"),
        [(1, "\n", 1), (3, "\n", 0), (3, "\r", 0), (3, "\u2028", 0)],
        ids=["within", "lf", "cr", "line-separator"],
    )
    def test_entry_point_count_is_bounded(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        entries: int,
        separator: str,
        kept: int,
    ) -> None:
        """Every line break :meth:`str.splitlines` honors counts toward the cap."""
        lines = ["[g]", *(f"e{i} = m:f" for i in range(entries))]
        text = separator.join(lines)
        _install(site, "manyep", metadata_files={"entry_points.txt": text})
        monkeypatch.setattr("peta.core.installation._MAX_ENTRY_POINT_LINES", 3)
        assert len(_inspect(site, "manyep").entry_points) == kept

    @pytest.mark.parametrize("separator", ["\n", "\r\n", "\r", "\u2028"])
    def test_installer_is_the_first_line(self, site: Path, separator: str) -> None:
        installer = f"  uv{separator}ignored{separator}"
        _install(site, "inst", metadata_files={"INSTALLER": installer})
        assert _inspect(site, "inst").installer == "uv"

    def test_top_level_txt_wins(self, site: Path) -> None:
        _install(
            site,
            "declared",
            files={"declared/__init__.py": b""},
            metadata_files={"top_level.txt": "alpha\nbeta\n"},
        )
        assert _inspect(site, "declared").import_packages == ["alpha", "beta"]

    def test_entry_point_order_is_deterministic(self, site: Path) -> None:
        _install(
            site,
            "dupes",
            metadata_files={"entry_points.txt": "[g]\nx = b.m\nx = a.m\n"},
        )
        values = [point.value for point in _inspect(site, "dupes").entry_points]
        assert values == sorted(values)

    def test_malformed_entry_points_do_not_abort(self, site: Path) -> None:
        _install(site, "badep", metadata_files={"entry_points.txt": "[g]\nnoequals\n"})
        assert _inspect(site, "badep").entry_points == []

    def test_entry_points(self, site: Path) -> None:
        _install(
            site,
            "tool",
            metadata_files={
                "entry_points.txt": (
                    "[console_scripts]\ntool = tool.cli:main\n\n"
                    "[peta.plugins]\nb = tool.b\na = tool.a\n"
                )
            },
        )
        points = [
            (point.group, point.name, point.value)
            for point in _inspect(site, "tool").entry_points
        ]
        assert points == [
            ("console_scripts", "tool", "tool.cli:main"),
            ("peta.plugins", "a", "tool.a"),
            ("peta.plugins", "b", "tool.b"),
        ]


class TestIntegrity:
    """Every file state, and the cases the issue calls out."""

    def test_hashes_are_opt_in(self, site: Path) -> None:
        _install(site, "lazy", files={"lazy.py": b"x = 1\n"})
        found = _inspect(site, "lazy")
        assert found.hashes_verified is False
        assert _states(found)["lazy.py"] == "unchecked"

    def test_verified_and_unhashed_rows_are_distinct(self, site: Path) -> None:
        _install(site, "good", files={"good.py": b"x = 1\n"})
        found = _inspect(site, "good", verify=True)
        states = _states(found)
        assert states["good.py"] == "verified"
        # RECORD cannot hash itself: absent, not corrupt.
        assert states["good-1.0.0.dist-info/RECORD"] == "not_recorded"
        assert found.state_counts()["mismatch"] == 0

    def test_modified_file_is_a_mismatch(self, site: Path) -> None:
        _install(site, "edited", files={"edited.py": b"x = 1\n"})
        _ = (site / "edited.py").write_bytes(b"x = 2\n")
        assert _states(_inspect(site, "edited", verify=True))["edited.py"] == "mismatch"

    def test_size_change_is_a_mismatch_without_hashing(self, site: Path) -> None:
        _install(site, "grown", files={"grown.py": b"x = 1\n"})
        _ = (site / "grown.py").write_bytes(b"x = 1\ny = 2\n")
        assert _states(_inspect(site, "grown"))["grown.py"] == "mismatch"

    def test_deleted_file_is_missing(self, site: Path) -> None:
        _install(site, "gone", files={"gone.py": b"x = 1\n"})
        (site / "gone.py").unlink()
        found = _inspect(site, "gone", verify=True)
        assert _states(found)["gone.py"] == "missing"
        assert found.files[0].size is None

    def test_unresolvable_legacy_entry_stays_out_of_bounds(self, site: Path) -> None:
        egg_info = site / "nulegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="nulegg"), encoding="utf-8"
        )
        (egg_info / "installed-files.txt").write_text(
            "../bad\x00.py\n", encoding="utf-8"
        )
        states = set(_states(_inspect(site, "nulegg", verify=True)).values())
        # POSIX refuses to resolve a NUL byte; Windows resolves it and then
        # cannot stat it. Either way nothing is read.
        assert states <= {"out_of_bounds", "unverifiable"}

    @pytest.mark.skipif(  # pragma: no cover
        sys.platform == "win32" or os.geteuid() == 0,
        reason="POSIX permissions, not bypassed by root",
    )
    def test_unreachable_file_is_unverifiable(self, site: Path) -> None:
        _install(site, "locked", files={"locked/a.py": b"x"})
        (site / "locked").chmod(0)
        try:
            states = _states(_inspect(site, "locked", verify=True))
        finally:
            (site / "locked").chmod(0o755)
        assert states["locked/a.py"] == "unverifiable"

    def test_undecodable_legacy_listing_is_still_evidence(self, site: Path) -> None:
        """Decoded with replacement characters, exactly as ``RECORD`` is."""
        egg_info = site / "latin-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="latin"), encoding="utf-8"
        )
        _ = (egg_info / "installed-files.txt").write_bytes(b"../bad\xe9.py\n")
        found = _inspect(site, "latin")
        assert found.record_source == "installed-files.txt"
        assert _states(found) == {"bad\ufffd.py": "missing"}

    def test_unreadable_during_hashing_is_unverifiable(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "denied", files={"denied.py": b"x"})

        def refuse(
            path: Path, algorithm: str, probed: os.stat_result, root: Path
        ) -> str:
            del algorithm, probed, root
            raise PermissionError(path)

        monkeypatch.setattr("peta.core.installation._digest", refuse)
        states = _states(_inspect(site, "denied", verify=True))
        assert states["denied.py"] == "unverifiable"

    @pytest.mark.parametrize("swap", ["replaced", "grown"])
    def test_file_changed_after_probing_is_unverifiable(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, swap: str
    ) -> None:
        """What is hashed must be the file whose containment was checked."""
        content = b"x = 1\n"
        _install(site, "racy", files={"racy.py": content})
        probe = installation._probe

        def probe_then_swap(root: Path, located: Path) -> os.stat_result | FileState:
            found = probe(root, located)
            if swap == "replaced":
                decoy = tmp_path / "decoy.py"
                _ = decoy.write_bytes(content)
                _ = decoy.replace(located)
            else:
                with located.open("ab") as handle:
                    _ = handle.write(b"# grown\n")
            return found

        monkeypatch.setattr("peta.core.installation._probe", probe_then_swap)
        states = _states(_inspect(site, "racy", verify=True))
        assert states["racy.py"] == "unverifiable"

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlink_swapped_in_after_probing_is_not_followed(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        content = b"x = 1\n"
        _install(site, "linked", files={"linked.py": content})
        outside = tmp_path / "outside.py"
        _ = outside.write_bytes(content)
        probe = installation._probe

        def probe_then_link(root: Path, located: Path) -> os.stat_result | FileState:
            found = probe(root, located)
            located.unlink()
            located.symlink_to(outside)
            return found

        monkeypatch.setattr("peta.core.installation._probe", probe_then_link)
        states = _states(_inspect(site, "linked", verify=True))
        assert states["linked.py"] == "unverifiable"

    @_posix_only("symlinks need privileges")  # pragma: no cover
    @pytest.mark.parametrize("verify", [True, False])
    def test_directory_swapped_in_after_resolving_is_not_followed(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        verify: bool,
    ) -> None:
        """No path component, not only the last, may lead out once checked."""
        content = b"x = 1\n"
        _install(site, "walked", files={"walked/mod.py": content})
        outside = tmp_path / "outside"
        outside.mkdir()
        _ = (outside / "mod.py").write_bytes(content)
        probe = installation._probe

        def swap_then_probe(root: Path, located: Path) -> os.stat_result | FileState:
            if located.name == "mod.py":
                package = located.parent
                package.rename(tmp_path / "moved")
                package.symlink_to(outside, target_is_directory=True)
            return probe(root, located)

        monkeypatch.setattr("peta.core.installation._probe", swap_then_probe)
        inspection = _inspect(site, "walked", verify=verify)
        assert _states(inspection)["walked/mod.py"] == "unverifiable"
        assert inspection.files[0].size is None

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_root_ancestor_swapped_in_after_resolving_is_not_followed(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An ancestor of the root itself, swapped for a symlink, is not followed."""
        content = b"x = 1\n"
        _install(site, "ancestor", files={"ancestor/mod.py": content})
        outside = (tmp_path / "outside").resolve()
        outside.mkdir()
        outside_site = outside / "lib" / "site-packages" / "ancestor"
        outside_site.mkdir(parents=True)
        _ = (outside_site / "mod.py").write_bytes(content)
        probe = installation._probe

        def swap_then_probe(root: Path, located: Path) -> os.stat_result | FileState:
            if located.name == "mod.py":
                env = site.parent
                env.rename(tmp_path / "env_moved")
                env.symlink_to(outside / "lib")
            return probe(root, located)

        monkeypatch.setattr("peta.core.installation._probe", swap_then_probe)
        inspection = _inspect(site, "ancestor", verify=True)
        assert _states(inspection)["ancestor/mod.py"] == "unverifiable"

    def test_refused_digest_is_unverifiable(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FIPS builds can list an algorithm yet refuse to construct it."""
        _install(site, "fips", files={"fips.py": b"x"})

        def refuse(name: str, *args: object, **kwargs: object) -> NoReturn:
            del args, kwargs
            raise ValueError(name)

        monkeypatch.setattr("peta.core.installation.hashlib.new", refuse)
        assert _states(_inspect(site, "fips", verify=True))["fips.py"] == "unverifiable"

    @pytest.mark.parametrize("record", [b"", b"\n"], ids=["empty", "blank-lines"])
    def test_present_record_outranks_a_stray_legacy_listing(
        self, site: Path, record: bytes
    ) -> None:
        dist_info = _install(site, "stray", record=False)
        _ = (dist_info / "RECORD").write_bytes(record)
        _ = (site / "stray.py").write_bytes(b"")
        (dist_info / "installed-files.txt").write_text(
            "../stray.py\n", encoding="utf-8"
        )
        assert _inspect(site, "stray").record_source is None

    def test_missing_record(self, site: Path) -> None:
        _install(site, "norecord", record=False)
        found = _inspect(site, "norecord", verify=True)
        assert found.record_source is None
        assert found.files == []

    def test_sources_txt_is_not_mistaken_for_installed_files(self, site: Path) -> None:
        """Without RECORD, importlib would report the source tree as installed."""
        egg_info = site / "srconly-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="srconly"), encoding="utf-8"
        )
        (egg_info / "SOURCES.txt").write_text("setup.py\nsrc/x.py\n", encoding="utf-8")
        assert _inspect(site, "srconly").record_source is None

    def test_legacy_installed_files_have_no_hashes(self, site: Path) -> None:
        egg_info = site / "oldpkg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="oldpkg"), encoding="utf-8"
        )
        _ = (site / "oldpkg.py").write_bytes(b"")
        (egg_info / "installed-files.txt").write_text(
            "../oldpkg.py\n../gone.py\n", encoding="utf-8"
        )
        found = _inspect(site, "oldpkg", verify=True)
        assert found.record_source == "installed-files.txt"
        assert _states(found) == {"oldpkg.py": "not_recorded", "gone.py": "missing"}

    def test_total_size_counts_what_is_on_disk(self, site: Path) -> None:
        dist_info = _install(site, "sized", files={"a.py": b"12345", "b.py": b"123"})
        (site / "b.py").unlink()
        record = (dist_info / "RECORD").stat().st_size
        assert _inspect(site, "sized").total_size == len(b"12345") + record


class TestHostileRecord:
    """RECORD rows a corrupt or hostile installer could have written."""

    def test_unknown_algorithm_is_unverifiable(self, site: Path) -> None:
        _ = (site / "weird.py").write_bytes(b"")
        _install(site, "weird", extra_rows=("weird.py,blake99=abc,0",))
        assert _states(_inspect(site, "weird", verify=True))["weird.py"] == (
            "unverifiable"
        )

    def test_hash_without_an_algorithm_is_unverifiable(self, site: Path) -> None:
        _ = (site / "bare.py").write_bytes(b"")
        _install(site, "bare", extra_rows=("bare.py,nodigest,0",))
        assert _states(_inspect(site, "bare", verify=True))["bare.py"] == (
            "unverifiable"
        )

    @_posix_only("no newlines in names")  # pragma: no cover
    def test_quoted_path_with_a_newline(self, site: Path) -> None:
        content = b"x"
        _ = (site / "odd\nname.py").write_bytes(content)
        row = f'"odd\nname.py",{_record_hash(content)},{len(content)}'
        _install(site, "oddname", extra_rows=(row,))
        states = _states(_inspect(site, "oddname", verify=True))
        assert states["odd\nname.py"] == "verified"

    @pytest.mark.parametrize(
        ("digest", "state"),
        [
            pytest.param("shake_128=abc", "unverifiable", id="variable-length"),
            pytest.param(None, "verified", id="uppercase-name"),
        ],
    )
    def test_algorithm_names(
        self, site: Path, digest: str | None, state: FileState
    ) -> None:
        content = b"x"
        _ = (site / "algo.py").write_bytes(content)
        recorded = digest or _record_hash(content).replace("sha256", "SHA256")
        _install(site, "algo", extra_rows=(f"algo.py,{recorded},{len(content)}",))
        assert _states(_inspect(site, "algo", verify=True))["algo.py"] == state

    def test_oversized_size_is_unrecorded(self, site: Path) -> None:
        _ = (site / "big.py").write_bytes(b"")
        _install(site, "big", extra_rows=("big.py,," + "9" * 5000,))
        (entry,) = [f for f in _inspect(site, "big").files if f.path == "big.py"]
        assert entry.recorded_size is None

    def test_non_ascii_digit_size_is_unrecorded(self, site: Path) -> None:
        _ = (site / "sup.py").write_bytes(b"")
        _install(site, "sup", extra_rows=("sup.py,,\u00b2",))
        (entry,) = [f for f in _inspect(site, "sup").files if f.path == "sup.py"]
        assert entry.recorded_size is None

    def test_unparsable_record_is_no_listing(self, site: Path) -> None:
        _install(site, "hugefield", extra_rows=('"' + "x" * 200_000,))
        assert _inspect(site, "hugefield", verify=True).record_source is None

    def test_unterminated_quote_is_no_listing(self, site: Path) -> None:
        _install(site, "unquoted", extra_rows=('"a.py,sha256=abc,1', "b.py,,"))
        assert _inspect(site, "unquoted").record_source is None

    @_posix_only("no CR in names")  # pragma: no cover
    def test_quoted_carriage_return_is_kept(self, site: Path) -> None:
        content = b"icon"
        _ = (site / "Icon\r").write_bytes(content)
        row = f'"Icon\r",{_record_hash(content)},{len(content)}'
        _install(site, "iconpkg", extra_rows=(row,))
        assert _states(_inspect(site, "iconpkg", verify=True))["Icon\r"] == "verified"

    def test_blank_record_lines_are_skipped(self, site: Path) -> None:
        _install(site, "blanks", files={"a.py": b"x"}, extra_rows=("",))
        assert "" not in _states(_inspect(site, "blanks"))

    def test_duplicate_record_paths_are_deduplicated(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Duplicate rows in RECORD are checked and hashed only once."""
        content = b"content"
        _ = (site / "dupe.py").write_bytes(content)
        row = f"dupe.py,{_record_hash(content)},{len(content)}"
        _install(site, "dupepkg", extra_rows=(row, row, row))
        mock_digest = MagicMock(side_effect=installation._digest)
        monkeypatch.setattr(installation, "_digest", mock_digest)
        inst = _inspect(site, "dupepkg", verify=True)
        assert [f.path for f in inst.files if f.path == "dupe.py"] == ["dupe.py"]
        assert mock_digest.call_count == 1

    @_posix_only("needs symlinks")  # pragma: no cover
    def test_distinct_paths_to_same_file_reuse_cached_digest(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aliased or symlinked paths to the same file are hashed only once."""
        content = b"shared"
        real_file = site / "real.py"
        _ = real_file.write_bytes(content)
        link_file = site / "link.py"
        link_file.symlink_to(real_file)
        row1 = f"real.py,{_record_hash(content)},{len(content)}"
        row2 = f"link.py,{_record_hash(content)},{len(content)}"
        _install(site, "aliascheck", extra_rows=(row1, row2))
        mock_digest = MagicMock(side_effect=installation._digest)
        monkeypatch.setattr(installation, "_digest", mock_digest)
        inst = _inspect(site, "aliascheck", verify=True)
        states = _states(inst)
        assert states["real.py"] == "verified"
        assert states["link.py"] == "verified"
        assert mock_digest.call_count == 1

    def test_duplicate_legacy_listing_paths_are_deduplicated(self, site: Path) -> None:
        """Duplicate rows in installed-files.txt are checked only once."""
        egg_info = site / "dupeegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="dupeegg"), encoding="utf-8"
        )
        _ = (site / "dupe.py").write_bytes(b"content")
        (egg_info / "installed-files.txt").write_text(
            "../dupe.py\n../dupe.py\n", encoding="utf-8"
        )
        inst = _inspect(site, "dupeegg")
        assert [f.path for f in inst.files] == ["dupe.py"]


class TestPathSafety:
    """A RECORD row can name any path; only the environment's are read."""

    @pytest.mark.parametrize(
        "row",
        [
            pytest.param("../../../outside.txt,sha256=abc,4", id="traversal"),
            pytest.param(f"{os.sep}outside.txt,sha256=abc,4", id="absolute"),
        ],
    )
    def test_escaping_rows_are_not_read(
        self, site: Path, tmp_path: Path, row: str
    ) -> None:
        _ = (tmp_path / "outside.txt").write_bytes(b"data")
        _install(site, "escape", extra_rows=(row,))
        found = _inspect(site, "escape", verify=True)
        escaped = [file for file in found.files if file.state == "out_of_bounds"]
        assert len(escaped) == 1
        assert escaped[0].size is None

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlink_out_of_the_environment_is_not_followed(
        self, site: Path, tmp_path: Path
    ) -> None:
        secret = tmp_path / "secret.txt"
        _ = secret.write_bytes(b"data")
        (site / "link.py").symlink_to(secret)
        _install(site, "linked", extra_rows=("link.py,sha256=abc,4",))
        assert _states(_inspect(site, "linked", verify=True))["link.py"] == (
            "out_of_bounds"
        )

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlink_loop_is_not_followed(self, site: Path) -> None:
        (site / "loop_a").symlink_to(site / "loop_b")
        (site / "loop_b").symlink_to(site / "loop_a")
        _install(site, "looped", extra_rows=("loop_a/x.py,sha256=abc,4",))
        (entry,) = _inspect(site, "looped", verify=True).files[:1]
        # 3.11/3.12 raise on the loop and later versions resolve it lexically;
        # either way nothing is read and the command does not fail.
        assert entry.state in {"out_of_bounds", "unverifiable"}
        assert entry.size is None

    def test_nul_byte_path_is_not_an_argument_error(self, site: Path) -> None:
        _install(site, "nulled", extra_rows=("bad\x00.py,sha256=abc,4",))
        (entry,) = [f for f in _inspect(site, "nulled").files if "\x00" in f.path]
        # POSIX refuses to resolve it; Windows' non-strict realpath returns it
        # unchanged. Either way it is never read.
        assert entry.state in {"out_of_bounds", "unverifiable"}
        assert entry.size is None

    @pytest.mark.parametrize(
        ("layout", "row"),
        [
            pytest.param(
                ("lib", "python3.12", "site-packages"), "../../../bin/tool", id="posix"
            ),
            pytest.param(
                (".local", "lib", "python3.12", "site-packages"),
                "../../../bin/tool",
                id="posix-user",
            ),
            pytest.param(
                ("Library", "Python", "3.12", "lib", "python", "site-packages"),
                "../../../bin/tool",
                id="macos-framework-user",
            ),
            pytest.param(
                ("lib", "python3.13t", "site-packages"),
                "../../../bin/tool",
                id="free-threaded",
            ),
            pytest.param(
                ("lib64", "python3.13", "site-packages"),
                "../../../bin/tool",
                id="posix-lib64",
            ),
            pytest.param(("Lib", "site-packages"), "../../Scripts/tool", id="windows"),
            pytest.param(
                ("Python312", "site-packages"), "../Scripts/tool", id="windows-user"
            ),
            pytest.param(
                ("Python312", "site-packages"),
                "../../share/doc.txt",
                id="windows-user-data",
            ),
        ],
    )
    def test_scripts_under_the_scheme_root_are_read(
        self, tmp_path: Path, layout: tuple[str, ...], row: str
    ) -> None:
        """Console scripts climb out of site-packages but stay in the scheme."""
        site = tmp_path.joinpath(*layout)
        site.mkdir(parents=True)
        script = (site / row).resolve()
        script.parent.mkdir(parents=True)
        content = b"#!python\n"
        _ = script.write_bytes(content)
        _install(
            site,
            "scripted",
            extra_rows=(f"{row},{_record_hash(content)},{len(content)}",),
        )
        assert _states(_inspect(site, "scripted", verify=True))[row] == "verified"

    def test_prefix_bounds_a_directory_outside_any_scheme(self, tmp_path: Path) -> None:
        """Without a scheme layout, only the target's own prefix admits scripts."""
        site = tmp_path / "custom"
        site.mkdir()
        script = tmp_path / "bin" / "tool"
        script.parent.mkdir()
        content = b"#!python\n"
        _ = script.write_bytes(content)
        row = f"../bin/tool,{_record_hash(content)},{len(content)}"
        _install(site, "scripted", extra_rows=(row,))
        path_only = _inspect(site, "scripted", verify=True)
        assert _states(path_only)["../bin/tool"] == "out_of_bounds"
        target = LocalTarget(
            paths=(str(site),),
            interpreter=None,
            marker_environment={},
            prefix=str(tmp_path),
        )
        with_prefix = inspect_installation("scripted", target=target, verify=True)
        assert _states(with_prefix)["../bin/tool"] == "verified"

    @pytest.mark.usefixtures("release_archives")
    def test_zipped_distribution_is_reported_not_read(self, tmp_path: Path) -> None:
        archive = tmp_path / "zpkg.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                "zpkg-1.0.0.dist-info/METADATA", _METADATA.format(name="zpkg")
            )
            bundle.writestr("zpkg-1.0.0.dist-info/RECORD", "zpkg.py,sha256=abc,1\n")
            bundle.writestr("zpkg.py", "x")
        target = LocalTarget(
            paths=(str(archive),), interpreter=None, marker_environment={}
        )
        found = inspect_installation("zpkg", target=target, verify=True)
        assert _states(found) == {"zpkg.py": "unverifiable"}

    @_posix_only("needs named pipes")  # pragma: no cover
    def test_recorded_fifo_does_not_block(self, site: Path) -> None:
        """A recorded FIFO is not a regular file and must not hang when probed."""
        assert sys.platform != "win32"
        pipe = site / "fifo_pkg" / "pipe"
        pipe.parent.mkdir(parents=True)
        os.mkfifo(pipe)
        _install(site, "recorded_fifo", extra_rows=("fifo_pkg/pipe,,",))
        states = _states(_inspect(site, "recorded_fifo"))
        assert states["fifo_pkg/pipe"] == "missing"
        states_verified = _states(_inspect(site, "recorded_fifo", verify=True))
        assert states_verified["fifo_pkg/pipe"] == "missing"


class TestMetadataSafety:
    """Metadata files are read before containment applies, so they are vetted."""

    @_posix_only("symlinks need privileges")  # pragma: no cover
    @pytest.mark.parametrize(
        "name", ["RECORD", "entry_points.txt", "direct_url.json", "INSTALLER"]
    )
    def test_symlinked_metadata_is_refused(
        self, site: Path, tmp_path: Path, name: str
    ) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("[g]\nleak = secret:line\n", encoding="utf-8")
        dist_info = _install(site, "linkmeta", record=name != "RECORD")
        (dist_info / name).unlink(missing_ok=True)
        (dist_info / name).symlink_to(secret)
        found = _inspect(site, "linkmeta")
        rendered = repr(found)
        assert "leak" not in rendered
        assert "secret:line" not in rendered

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlinked_legacy_listing_is_refused(
        self, site: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "listing.txt"
        outside.write_text("../leaked.py\n", encoding="utf-8")
        egg_info = site / "linkegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="linkegg"), encoding="utf-8"
        )
        (egg_info / "installed-files.txt").symlink_to(outside)
        assert _inspect(site, "linkegg").record_source is None

    @_posix_only("needs named pipes")  # pragma: no cover
    def test_special_file_is_not_read(self, site: Path) -> None:
        """A FIFO would block forever if it were opened for reading."""
        assert sys.platform != "win32"  # narrows os.mkfifo for type checkers
        dist_info = _install(site, "fifo", record=False)
        os.mkfifo(dist_info / "RECORD")
        assert _inspect(site, "fifo").record_source is None

    @pytest.mark.parametrize("swap", ["replaced", "symlinked"])
    def test_metadata_swapped_after_vetting_is_not_read(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, swap: str
    ) -> None:
        """What is read must be the metadata file that was vetted."""
        if swap == "symlinked" and sys.platform == "win32":  # pragma: no cover
            pytest.skip("symlinks need privileges")
        _install(site, "swapped", metadata_files={"INSTALLER": "pip\n"})
        outside = tmp_path / "outside.txt"
        _ = outside.write_text("leaked\n", encoding="utf-8")
        vet = installation._plain_file

        def vet_then_swap(
            path: Path, policy: installation._ReadPolicy
        ) -> os.stat_result | None:
            found = vet(path, policy)
            if path.name == "INSTALLER":
                path.unlink()
                if swap == "replaced":
                    _ = outside.replace(path)
                else:
                    path.symlink_to(outside)
            return found

        monkeypatch.setattr("peta.core.installation._plain_file", vet_then_swap)
        assert _inspect(site, "swapped").installer is None

    def test_oversized_metadata_is_refused(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "huge", files={"huge.py": b"x"})
        monkeypatch.setattr("peta.core.installation._MAX_METADATA_BYTES", 1)
        assert _inspect(site, "huge").record_source is None

    def test_small_metadata_has_its_own_limit(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The listing's allowance does not extend to files that are tiny."""
        _install(
            site,
            "dense",
            files={"dense.py": b"x"},
            metadata_files={"INSTALLER": "pip\n" + "x\n" * 100},
        )
        monkeypatch.setattr("peta.core.installation._MAX_SMALL_METADATA_BYTES", 64)
        found = _inspect(site, "dense")
        assert found.installer is None
        assert found.record_source == "RECORD"

    @pytest.mark.parametrize(("rows", "source"), [(2, "RECORD"), (3, None)])
    def test_record_row_count_is_bounded(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        rows: int,
        source: RecordSource | None,
    ) -> None:
        dist_info = _install(site, "many", record=False)
        _ = (dist_info / "RECORD").write_text("a,,\n" * rows, encoding="utf-8")
        monkeypatch.setattr("peta.core.installation._MAX_RECORD_ROWS", 2)
        assert _inspect(site, "many").record_source == source

    @pytest.mark.parametrize(
        ("record", "source"),
        [
            pytest.param("abcdef,,\n" * 5, "RECORD", id="each-row-within"),
            pytest.param("a" + "," * 20 + "\n", None, id="too-wide"),
            pytest.param('"a\nb\nc\nd\ne\nf",,\n', None, id="too-many-lines"),
        ],
    )
    def test_record_row_length_is_bounded(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        record: str,
        source: RecordSource | None,
    ) -> None:
        dist_info = _install(site, "wide", record=False)
        _ = (dist_info / "RECORD").write_text(record, encoding="utf-8", newline="")
        monkeypatch.setattr("peta.core.installation._MAX_RECORD_ROW_CHARS", 10)
        assert _inspect(site, "wide").record_source == source

    def test_extra_record_columns_are_ignored(self, site: Path) -> None:
        dist_info = _install(site, "extra", record=False)
        _ = (dist_info / "RECORD").write_text("a.py,,7,more,cols\n", encoding="utf-8")
        (found,) = _inspect(site, "extra").files
        assert found.recorded_size == 7

    @pytest.mark.parametrize(
        ("separator", "source"),
        [("", "installed-files.txt"), ("\n", None), ("\r", None), ("\u2028", None)],
        ids=["one-line", "lf", "cr", "line-separator"],
    )
    def test_legacy_listing_is_bounded(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        separator: str,
        source: RecordSource | None,
    ) -> None:
        """Every line break :meth:`str.splitlines` honors counts toward the cap."""
        egg_info = site / "manyegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="manyegg"), encoding="utf-8"
        )
        names = ["../a.py", "../b.py", "../c.py"]
        listing = separator.join(names) if separator else names[0]
        (egg_info / "installed-files.txt").write_text(
            listing, encoding="utf-8", newline=""
        )
        monkeypatch.setattr("peta.core.installation._MAX_RECORD_ROWS", 2)
        assert _inspect(site, "manyegg").record_source == source

    def test_directory_in_place_of_record_is_no_listing(self, site: Path) -> None:
        dist_info = _install(site, "dirrec", record=False)
        (dist_info / "RECORD").mkdir()
        (dist_info / "installed-files.txt").write_text("../x.py\n", encoding="utf-8")
        assert _inspect(site, "dirrec").record_source is None

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlinked_metadata_directory_is_refused(
        self, site: Path, tmp_path: Path
    ) -> None:
        secret_dir = tmp_path / "secret.dist-info"
        secret_dir.mkdir()
        (secret_dir / "METADATA").write_text(
            _METADATA.format(name="linkdir"), encoding="utf-8"
        )
        (secret_dir / "RECORD").write_text(
            "secret.py,sha256=xxx,123\n", encoding="utf-8"
        )
        (site / "linkdir-1.0.0.dist-info").symlink_to(secret_dir)
        found = _inspect(site, "linkdir")
        assert found.record_source is None
        assert found.files == []

    @pytest.mark.parametrize(
        ("length", "source"), [(10, "installed-files.txt"), (11, None)]
    )
    def test_legacy_listing_line_length_is_bounded(
        self,
        site: Path,
        monkeypatch: pytest.MonkeyPatch,
        length: int,
        source: RecordSource | None,
    ) -> None:
        egg_info = site / "longegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="longegg"), encoding="utf-8"
        )
        entry = "../" + "a" * (length - 6) + ".py"
        (egg_info / "installed-files.txt").write_text(entry + "\n", encoding="utf-8")
        monkeypatch.setattr("peta.core.installation._MAX_RECORD_ROW_CHARS", 10)
        assert _inspect(site, "longegg").record_source == source

    def test_legacy_listing_is_parsed_from_the_vetted_text(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A listing rewritten after vetting is not read a second time."""
        egg_info = site / "vettedegg-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="vettedegg"), encoding="utf-8"
        )
        (egg_info / "installed-files.txt").write_text("../kept.py\n", encoding="utf-8")
        read = installation._read_text

        def read_then_rewrite(
            dist: importlib.metadata.Distribution, name: str
        ) -> str | None:
            text = read(dist, name)
            if name == "installed-files.txt":
                _ = (egg_info / name).write_text("../swapped.py\n", encoding="utf-8")
            return text

        monkeypatch.setattr("peta.core.installation._read_text", read_then_rewrite)
        assert list(_states(_inspect(site, "vettedegg"))) == ["kept.py"]

    def test_entry_points_are_parsed_from_the_vetted_text(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file rewritten after vetting is not read a second time."""
        dist_info = _install(
            site, "vetted", metadata_files={"entry_points.txt": "[g]\nkept = m:f\n"}
        )
        read = installation._read_text

        def read_then_rewrite(
            dist: importlib.metadata.Distribution, name: str
        ) -> str | None:
            text = read(dist, name)
            if name == "entry_points.txt":
                rewritten = "[g]\nswapped = m:f\n"
                _ = (dist_info / name).write_text(rewritten, encoding="utf-8")
            return text

        monkeypatch.setattr("peta.core.installation._read_text", read_then_rewrite)
        points = _inspect(site, "vetted").entry_points
        assert [point.name for point in points] == ["kept"]


def _write_metadata(site: Path, name: str, extra: str) -> None:
    dist_info = _install(site, name)
    metadata = _METADATA.format(name=name) + extra
    _ = (dist_info / "METADATA").write_text(metadata, encoding="utf-8")


class TestCoreMetadata:
    """The ``METADATA`` that names the package, and how it is found."""

    def test_undecodable_core_metadata_is_not_found(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Core metadata is UTF-8; a damaged file names no package."""
        dist_info = _install(site, "damaged")
        damaged = _METADATA.format(name="damaged").encode() + b"Summary: \xff\n"
        _ = (dist_info / "METADATA").write_bytes(damaged)
        monkeypatch.syspath_prepend(str(site))
        with pytest.raises(PackageNotFoundError):
            _ = inspect_installation("damaged")

    def test_long_description_is_not_parsed_as_headers(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the header block is read; the body cannot rename the package."""
        _write_metadata(site, "headers", "\nName: impostor\nVersion: 9\n")
        monkeypatch.syspath_prepend(str(site))
        found = inspect_installation("headers")
        assert (found.name, found.version) == ("headers", "1.0.0")

    @pytest.mark.parametrize("field", ["Name", "Version"])
    def test_oversized_core_field_is_not_found(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, field: str
    ) -> None:
        """A value past the limit is no value, however much else is there."""
        dist_info = _install(site, "longfield")
        value = "longfield" + " " * 300 + "x" if field == "Name" else "1" * 300
        other = "Version: 1.0.0" if field == "Name" else "Name: longfield"
        metadata = f"Metadata-Version: 2.1\n{field}: {value}\n{other}\n"
        _ = (dist_info / "METADATA").write_text(metadata, encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        with pytest.raises(PackageNotFoundError):
            _ = inspect_installation("longfield")

    def test_unreadable_metadata_on_an_explicit_path_is_not_found(
        self, site: Path
    ) -> None:
        """The lookup reads each candidate's METADATA before the inspection does."""
        dist_info = _install(site, "badmeta")
        _ = (dist_info / "METADATA").write_bytes(b"Name: badmeta\n\xff\xfe\n")
        result = runner.invoke(
            app, ["origin", "badmeta", "--path", str(site), "--json"]
        )
        assert result.exit_code == 1, result.output
        assert json.loads(result.output)["errors"][0]["code"] == "package_not_found"

    @pytest.mark.parametrize(
        "metadata",
        [
            "Metadata-Version: 2.1\nName: partial\n",
            "Metadata-Version: 2.1\nName:  \nVersion: 1.0.0\n",
        ],
        ids=["no-version", "blank-name"],
    )
    def test_incomplete_metadata_is_not_found(
        self, site: Path, monkeypatch: pytest.MonkeyPatch, metadata: str
    ) -> None:
        """Found by its directory name alone, on the running path."""
        dist_info = _install(site, "partial")
        _ = (dist_info / "METADATA").write_text(metadata, encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        with pytest.raises(PackageNotFoundError):
            _ = inspect_installation("partial")

    @_posix_only("symlinks need privileges")  # pragma: no cover
    def test_symlinked_core_metadata_is_followed(
        self, site: Path, tmp_path: Path
    ) -> None:
        """A symlink-tree environment, as Nix builds, links every file."""
        dist_info = _install(site, "linked")
        store = tmp_path / "store-METADATA"
        _ = store.write_text(_METADATA.format(name="linked"), encoding="utf-8")
        (dist_info / "METADATA").unlink()
        (dist_info / "METADATA").symlink_to(store)
        assert _inspect(site, "linked").version == "1.0.0"

    @_posix_only("no /dev/zero")  # pragma: no cover
    def test_core_metadata_linked_to_a_device_is_not_read(self, site: Path) -> None:
        dist_info = _install(site, "endless")
        (dist_info / "METADATA").unlink()
        (dist_info / "METADATA").symlink_to("/dev/zero")
        with pytest.raises(PackageNotFoundError):
            _ = _inspect(site, "endless")

    def test_oversized_core_metadata_is_not_read(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "bulky")
        monkeypatch.setattr("peta.core.installation._MAX_CORE_METADATA_BYTES", 8)
        with pytest.raises(PackageNotFoundError):
            _ = _inspect(site, "bulky")

    def test_metadata_naming_another_package_is_not_found(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The runtime lookup matches the directory name, not the metadata."""
        dist_info = _install(site, "foo")
        _ = (dist_info / "METADATA").write_text(
            _METADATA.format(name="bar"), encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(site))
        with pytest.raises(PackageNotFoundError):
            _ = inspect_installation("foo")

    def test_metadata_name_is_matched_canonically(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "Dotted.Name")
        monkeypatch.syspath_prepend(str(site))
        assert inspect_installation("dotted-name").name == "Dotted.Name"


class TestZippedDistributions:
    """Distributions inside a zip on the search path, whose members are read."""

    @pytest.mark.usefixtures("release_archives")
    def test_oversized_archive_member_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        archive = tmp_path / "oversized.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                "oversized-1.0.0.dist-info/METADATA", _METADATA.format(name="oversized")
            )
            bundle.writestr(
                "oversized-1.0.0.dist-info/RECORD", "pkg.py,sha256=xxx,123\n"
            )
        monkeypatch.setattr("peta.core.installation._MAX_METADATA_BYTES", 1)
        target = LocalTarget(
            paths=(str(archive),), interpreter=None, marker_environment={}
        )
        found = inspect_installation("oversized", target=target)
        assert found.record_source is None

    @pytest.mark.usefixtures("release_archives")
    def test_corrupt_archive_member_is_unreadable(self, tmp_path: Path) -> None:
        archive = tmp_path / "corrupt.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(
                "corrupt-1.0.0.dist-info/METADATA", _METADATA.format(name="corrupt")
            )
            bundle.writestr("corrupt-1.0.0.dist-info/RECORD", "pkg.py,sha256=xxx,123\n")
        data = bytearray(archive.read_bytes())
        cd = data.find(b"PK\x01\x02")
        cd2 = data.find(b"PK\x01\x02", cd + 1)
        data[cd2 + 16] ^= 0xFF
        archive.write_bytes(data)

        target = LocalTarget(
            paths=(str(archive),), interpreter=None, marker_environment={}
        )
        found = inspect_installation("corrupt", target=target)
        assert found.record_source is None
        assert found.files == []

    @pytest.mark.usefixtures("release_archives")
    def test_unreadable_metadata_is_a_structured_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A zipped distribution on the running path whose METADATA fails its CRC."""
        archive = tmp_path / "badmeta.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                "badmeta-1.0.0.dist-info/METADATA", _METADATA.format(name="badmeta")
            )
        data = bytearray(archive.read_bytes())
        data[data.find(b"PK\x01\x02") + 16] ^= 0xFF
        archive.write_bytes(data)
        monkeypatch.syspath_prepend(str(archive))

        result = runner.invoke(app, ["origin", "badmeta", "--json"])
        assert result.exit_code == 1, result.output
        assert json.loads(result.output)["errors"][0]["code"] == "package_not_found"

    @pytest.mark.usefixtures("release_archives")
    @pytest.mark.parametrize(
        "damage",
        [
            "lzma-stream",
            pytest.param(
                "zstd-stream",
                marks=pytest.mark.skipif(
                    not hasattr(zipfile, "ZIP_ZSTANDARD"), reason="Python 3.14+"
                ),
            ),
            "encrypted",
            "unknown-method",
        ],
    )
    def test_undecompressable_archive_member_is_unreadable(
        self, tmp_path: Path, damage: str
    ) -> None:
        archive = tmp_path / "packed.zip"
        # The compression method, and how many leading bytes of its stream
        # (LZMA properties, the Zstandard magic) to leave intact.
        method, kept = _CORRUPTIBLE.get(damage, (zipfile.ZIP_STORED, 0))
        with zipfile.ZipFile(archive, "w", compression=method) as bundle:
            bundle.writestr(
                "packed-1.0.0.dist-info/METADATA", _METADATA.format(name="packed")
            )
            bundle.writestr("packed-1.0.0.dist-info/RECORD", "pkg.py,,\n" * 50)
        with zipfile.ZipFile(archive) as bundle:
            member = bundle.getinfo("packed-1.0.0.dist-info/RECORD")
        data = bytearray(archive.read_bytes())
        local = member.header_offset
        central = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 1)
        if damage in _CORRUPTIBLE:
            # Past the stream's header, so the decoder itself rejects it.
            start = local + 30 + len(member.filename) + kept
            end = local + 30 + len(member.filename) + member.compress_size
            data[start:end] = b"\xff" * (end - start)
        elif damage == "encrypted":
            data[local + 6] |= 1
            data[central + 8] |= 1
        else:
            data[local + 8 : local + 10] = (99).to_bytes(2, "little")
            data[central + 10 : central + 12] = (99).to_bytes(2, "little")
        archive.write_bytes(data)

        target = LocalTarget(
            paths=(str(archive),), interpreter=None, marker_environment={}
        )
        found = inspect_installation("packed", target=target)
        assert found.record_source is None
        assert found.files == []


class TestCli:
    """The ``peta origin`` command end to end."""

    def test_json_preserves_structured_origin_and_file_states(self, site: Path) -> None:
        direct_url = {"url": "file:///home/dev/src/clipkg", "dir_info": {}}
        _install(
            site,
            "clipkg",
            files={"clipkg/__init__.py": b""},
            metadata_files={"direct_url.json": json.dumps(direct_url)},
        )
        result = runner.invoke(
            app, ["origin", "clipkg", "--path", str(site), "--verify", "--json"]
        )
        assert result.exit_code == 0, result.output
        envelope = json.loads(result.output)
        assert envelope["query"]["command"] == "origin"
        assert envelope["query"]["arguments"]["verify"] is True
        assert envelope["status"] == "success"
        body = envelope["result"]
        assert body["origin"]["kind"] == "directory"
        assert body["origin"]["url"] == "file:///home/dev/src/clipkg"
        assert body["integrity"]["hashes_verified"] is True
        assert body["integrity"]["states"]["verified"] == 1
        assert {"path": "clipkg/__init__.py", "state": "verified"}.items() <= (
            body["files"][0].items()
        )

    @pytest.mark.parametrize("output_format", ["rich", "text", "markdown"])
    def test_human_output_hides_local_paths(
        self, site: Path, output_format: str
    ) -> None:
        direct_url = {
            "url": "file:///home/dev/private/clipkg",
            "dir_info": {"editable": True},
        }
        _install(
            site, "clipkg", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        result = runner.invoke(
            app, ["origin", "clipkg", "--path", str(site), "--format", output_format]
        )
        assert result.exit_code == 0, result.output
        assert "/home/dev/private" not in result.output
        assert "clipkg" in result.output
        assert "editable" in result.output

    def test_flagged_files_are_listed(self, site: Path) -> None:
        _install(site, "broken", files={"broken.py": b"x = 1\n"})
        (site / "broken.py").unlink()
        result = runner.invoke(
            app, ["origin", "broken", "--path", str(site), "--format", "text"]
        )
        assert result.exit_code == 0
        assert "missing\tbroken.py" in result.output

    def test_parse_error_names_the_origin_command(self) -> None:
        result = runner.invoke(app, ["origin", "x", "--bogus", "--json"])
        assert result.exit_code == 2
        assert json.loads(result.output)["query"]["command"] == "origin"

    def test_empty_name_is_an_argument_error(self) -> None:
        result = runner.invoke(app, ["origin", "", "--json"])
        assert result.exit_code == 2
        assert json.loads(result.output)["errors"][0]["code"] == "invalid_arguments"

    def test_not_found(self, site: Path) -> None:
        result = runner.invoke(app, ["origin", "absent", "--path", str(site), "--json"])
        assert result.exit_code == 1
        assert json.loads(result.output)["errors"][0]["code"] == "package_not_found"
        with pytest.raises(PackageNotFoundError):
            _inspect(site, "absent")

    def test_invalid_target(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["origin", "x", "--path", str(tmp_path / "nope"), "--json"]
        )
        assert result.exit_code == 2
        assert json.loads(result.output)["errors"][0]["code"] == "invalid_arguments"

    @pytest.mark.parametrize("output_format", ["text", "markdown"])
    def test_single_letter_scheme_url_is_preserved_in_human_output(
        self, site: Path, output_format: str
    ) -> None:
        direct_url = {
            "url": "x://example.com/private/repo",
            "vcs_info": {"vcs": "git", "commit_id": "0123456789abcdef"},
        }
        _install(
            site, "xpkg", metadata_files={"direct_url.json": json.dumps(direct_url)}
        )
        result = runner.invoke(
            app, ["origin", "xpkg", "--path", str(site), "--format", output_format]
        )
        assert result.exit_code == 0, result.output
        assert "x://example.com/private/repo" in result.output

    def test_mismatched_metadata_name_aborts_before_record(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist_info = site / "spoofed-1.0.0.dist-info"
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: actual-pkg\nVersion: 1.0.0\n",
            encoding="utf-8",
        )
        (dist_info / "RECORD").write_text("actual/mod.py,,\n", encoding="utf-8")

        record_mock = MagicMock()
        monkeypatch.setattr(installation, "_record_files", record_mock)

        with pytest.raises(PackageNotFoundError):
            _inspect(site, "spoofed")

        record_mock.assert_not_called()
