"""Origin and file-integrity inspection against real metadata directories.

Each fixture lays out a ``site-packages`` directory by hand, the way an
installer would, so every origin kind and every file state is exercised
against real files rather than a mocked ``Distribution``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import zipfile
from typing import TYPE_CHECKING, NoReturn

import pytest
from typer.testing import CliRunner

from peta.cli.app import app
from peta.core.installation import inspect_installation
from peta.core.local import LocalTarget, PackageNotFoundError

if TYPE_CHECKING:
    from pathlib import Path

    from peta.core.installation import FileState, Installation

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
                '{"url": "https://example.com/\\ud800", "archive_info": {}}',
                "malformed url",
                id="surrogate-url",
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

    @pytest.mark.skipif(
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

    def test_undecodable_legacy_listing_is_no_listing(self, site: Path) -> None:
        egg_info = site / "latin-1.0.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            _METADATA.format(name="latin"), encoding="utf-8"
        )
        _ = (egg_info / "installed-files.txt").write_bytes(b"../bad\xe9.py\n")
        assert _inspect(site, "latin").record_source is None

    def test_unreadable_during_hashing_is_unverifiable(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "denied", files={"denied.py": b"x"})

        def refuse(path: Path, algorithm: str) -> str:
            del algorithm
            raise PermissionError(path)

        monkeypatch.setattr("peta.core.installation._digest", refuse)
        states = _states(_inspect(site, "denied", verify=True))
        assert states["denied.py"] == "unverifiable"

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

    @pytest.mark.skipif(sys.platform == "win32", reason="no newlines in names")
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

    @pytest.mark.skipif(sys.platform == "win32", reason="no CR in names")
    def test_quoted_carriage_return_is_kept(self, site: Path) -> None:
        content = b"icon"
        _ = (site / "Icon\r").write_bytes(content)
        row = f'"Icon\r",{_record_hash(content)},{len(content)}'
        _install(site, "iconpkg", extra_rows=(row,))
        assert _states(_inspect(site, "iconpkg", verify=True))["Icon\r"] == "verified"

    def test_blank_record_lines_are_skipped(self, site: Path) -> None:
        _install(site, "blanks", files={"a.py": b"x"}, extra_rows=("",))
        assert "" not in _states(_inspect(site, "blanks"))


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

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
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

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
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


class TestMetadataSafety:
    """Metadata files are read before containment applies, so they are vetted."""

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
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

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
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

    @pytest.mark.skipif(sys.platform == "win32", reason="needs named pipes")
    def test_special_file_is_not_read(self, site: Path) -> None:
        """A FIFO would block forever if it were opened for reading."""
        assert sys.platform != "win32"  # narrows os.mkfifo for type checkers
        dist_info = _install(site, "fifo", record=False)
        os.mkfifo(dist_info / "RECORD")
        assert _inspect(site, "fifo").record_source is None

    def test_oversized_metadata_is_refused(
        self, site: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(site, "huge", files={"huge.py": b"x"})
        monkeypatch.setattr("peta.core.installation._MAX_METADATA_BYTES", 1)
        assert _inspect(site, "huge").record_source is None

    def test_directory_in_place_of_record_is_no_listing(self, site: Path) -> None:
        dist_info = _install(site, "dirrec", record=False)
        (dist_info / "RECORD").mkdir()
        (dist_info / "installed-files.txt").write_text("../x.py\n", encoding="utf-8")
        assert _inspect(site, "dirrec").record_source is None

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
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
