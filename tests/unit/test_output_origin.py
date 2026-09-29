"""Unit tests for the ``origin`` renderers, from hand-built installations."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast, get_args

import pytest

from peta.cli.output.installation import (
    describe_origin,
    flagged_files,
    installation_notes,
    installation_rows,
)
from peta.cli.output.json import format_origin
from peta.cli.output.markdown import format_origin as markdown_origin
from peta.cli.output.tables import render_origin
from peta.cli.output.text import format_origin as text_origin
from peta.core.installation import (
    FILE_STATES,
    EntryPoint,
    FileState,
    Installation,
    InstalledFile,
    Origin,
)

pytestmark = pytest.mark.unit

GENERATED_AT = "2026-09-28T12:00:00Z"


def _installation(**over: object) -> Installation:
    base = Installation(
        name="demo",
        version="1.0.0",
        origin=Origin(kind="index"),
        installer="uv",
        requested=True,
        import_packages=["demo"],
        entry_points=[EntryPoint("console_scripts", "demo", "demo.cli:main")],
        record_source="RECORD",
        files=[
            InstalledFile("demo/__init__.py", "verified", 10, 10, "sha256=x"),
            InstalledFile("demo/core.py", "mismatch", 12, 10, "sha256=y"),
            InstalledFile("demo-1.0.0.dist-info/RECORD", "not_recorded", 99),
        ],
        hashes_verified=True,
    )
    return replace(base, **over)


def test_file_states_match_the_alias() -> None:
    assert set(get_args(FileState.__value__)) == set(FILE_STATES)


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        pytest.param(
            Origin(kind="index"), "package index (no direct_url.json)", id="index"
        ),
        pytest.param(
            Origin(
                kind="vcs",
                url="https://github.com/org/demo.git",
                vcs="git",
                requested_revision="main",
                commit_id="0123456789abcdef0123",
            ),
            "git https://github.com/org/demo.git @ main -> 0123456789ab",
            id="vcs",
        ),
        pytest.param(
            Origin(
                kind="archive",
                url="https://example.com/demo.tar.gz",
                archive_hashes={"md5": "0" * 32, "sha256": "f" * 64},
            ),
            "archive https://example.com/demo.tar.gz (sha256:ffffffffffff...)",
            id="archive",
        ),
        pytest.param(
            Origin(kind="directory", url="file:///home/me/demo", editable=True),
            "local directory .../demo (editable)",
            id="editable",
        ),
        pytest.param(
            Origin(kind="vcs", url="file:///srv/repos/demo", vcs="git"),
            "git .../demo",
            id="local-vcs",
        ),
        pytest.param(
            Origin(kind="directory", url="file:///home/me/mono", subdirectory="pkg"),
            "local directory .../mono [subdirectory pkg]",
            id="subdirectory",
        ),
        pytest.param(
            Origin(kind="unknown", reason="direct_url.json has no url."),
            "unknown (direct_url.json has no url.)",
            id="unknown",
        ),
    ],
)
def test_describe_origin(origin: Origin, expected: str) -> None:
    assert describe_origin(origin) == expected


def test_archive_prefers_sha2_over_md5() -> None:
    origin = Origin(
        kind="archive",
        url="https://example.com/a.tar.gz",
        archive_hashes={"md5": "0" * 32, "sha512": "e" * 128},
    )
    assert "sha512:eeee" in describe_origin(origin)


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        pytest.param(
            Origin(kind="directory", url="file:///"),
            "local directory local path",
            id="root-path",
        ),
        pytest.param(
            Origin(kind="directory", url="file:C:\\Users\\Alice\\private\\pkg"),
            "local directory .../pkg",
            id="windows-backslashes",
        ),
        pytest.param(
            Origin(kind="directory", url="file:///C:%5CUsers%5CAlice%5Cpkg"),
            "local directory .../pkg",
            id="windows-encoded-backslashes",
        ),
        pytest.param(
            Origin(kind="directory", url="/home/alice/private/pkg"),
            "local directory .../pkg",
            id="posix-absolute-path",
        ),
        pytest.param(
            Origin(kind="directory", url=r"\\server\share\pkg"),
            "local directory .../pkg",
            id="unc-path",
        ),
        pytest.param(
            Origin(kind="directory", url="C:\\Users\\Alice\\private\\pkg"),
            "local directory .../pkg",
            id="windows-drive-path",
        ),
        pytest.param(
            Origin(kind="archive", url="https://example.com/a.tar.gz"),
            "archive https://example.com/a.tar.gz",
            id="archive-without-hashes",
        ),
    ],
)
def test_describe_origin_edges(origin: Origin, expected: str) -> None:
    assert describe_origin(origin) == expected


def test_every_flagged_state_is_explained() -> None:
    odd = _installation(
        files=[
            InstalledFile("a.py", "unverifiable", 1, 1, "blake99=x"),
            InstalledFile("../../x", "out_of_bounds"),
        ]
    )
    notes = " ".join(installation_notes(odd))
    assert "Unverifiable" in notes
    assert "outside the selected environment" in notes


def test_rows_summarize_integrity() -> None:
    rows = dict(installation_rows(_installation()))
    assert rows["Installer"] == "uv (requested)"
    assert rows["Integrity"] == "1 verified, 1 mismatch, 1 not recorded"
    assert rows["Files"].startswith("3 listed in RECORD")


def test_no_record_is_said_plainly() -> None:
    rows = dict(installation_rows(_installation(record_source=None, files=[])))
    assert rows["Files"] == "no readable RECORD; file integrity unavailable"
    assert "Integrity" not in rows


def test_only_problem_files_are_flagged() -> None:
    assert [file.path for file in flagged_files(_installation())] == ["demo/core.py"]


def test_unverified_run_says_how_to_verify() -> None:
    unchecked = _installation(
        files=[InstalledFile("a.py", "unchecked", 1, 1, "sha256=x")],
        hashes_verified=False,
    )
    assert any("--verify" in note for note in installation_notes(unchecked))


def test_json_result_shape() -> None:
    data = json.loads(format_origin(_installation(), generated_at=GENERATED_AT))
    assert data["query"]["command"] == "origin"
    assert data["status"] == "success"
    assert data["sources"][0]["name"] == "local"
    result = cast("dict[str, object]", data["result"])
    integrity = cast("dict[str, object]", result["integrity"])
    assert integrity["states"] == {
        "verified": 1,
        "mismatch": 1,
        "missing": 0,
        "not_recorded": 1,
        "unverifiable": 0,
        "unchecked": 0,
        "out_of_bounds": 0,
    }
    assert integrity["file_count"] == len(_installation().files)
    assert result["entry_points"] == [
        {"group": "console_scripts", "name": "demo", "value": "demo.cli:main"}
    ]
    files = cast("list[dict[str, object]]", result["files"])
    assert files[1] == {
        "path": "demo/core.py",
        "state": "mismatch",
        "size": 12,
        "recorded_size": 10,
        "recorded_hash": "sha256=y",
    }


def test_markdown_escapes_untrusted_values() -> None:
    hostile = _installation(
        name="![x](https://evil.invalid/p.png)",
        files=[InstalledFile("a|b`.py", "missing")],
    )
    rendered = markdown_origin(hostile)
    assert "![x](" not in rendered
    assert "| missing | ``a\\|b`.py`` |" in rendered


def test_text_keeps_untrusted_values_on_one_line() -> None:
    hostile = _installation(files=[InstalledFile("a\nforged.py", "missing")])
    assert "missing\ta forged.py" in text_origin(hostile)


def test_rich_lists_flagged_files_after_the_panel() -> None:
    rendered = render_origin(_installation(), color=False)
    assert "mismatch  demo/core.py" in rendered
    assert "\n\n\n" not in rendered
