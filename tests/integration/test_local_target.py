"""Integration: explicit environment targeting against a real metadata tree.

Builds a ``site-packages`` directory on disk that the interpreter running the
suite knows nothing about, which is the situation an isolated ``uvx peta`` /
``pipx run peta`` install is in: the package under inspection is installed
somewhere the running interpreter cannot see.
"""

from __future__ import annotations

import json
import subprocess  # ruff: ignore[suspicious-subprocess-import] # Only for CompletedProcess.
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import app
from peta.core.deptree import build_tree
from peta.core.local import LocalTarget, PackageNotFoundError, get_package

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration
runner = CliRunner()

_PROBE = """\
Metadata-Version: 2.1
Name: probe
Version: 1.0.0
Summary: Marker evaluation probe.
Requires-Dist: probe-dep ; python_version < "3.14"
"""

_PROBE_DEP = """\
Metadata-Version: 2.1
Name: probe-dep
Version: 2.0.0
Summary: Only reachable when the target's markers allow it.
"""


def _markers(**over: str) -> dict[str, str]:
    base = {
        "implementation_name": "cpython",
        "implementation_version": "3.13.15",
        "os_name": "posix",
        "platform_machine": "arm64",
        "platform_python_implementation": "CPython",
        "platform_release": "25.0.0",
        "platform_system": "Darwin",
        "platform_version": "irrelevant",
        "python_full_version": "3.13.15",
        "python_version": "3.13",
        "sys_platform": "darwin",
    }
    return base | over


@pytest.fixture
def site_packages(tmp_path: Path) -> Path:
    """Return a metadata directory holding ``probe`` and ``probe-dep``.

    Returns:
        A directory usable as a ``--path`` target.
    """
    root = tmp_path / "site-packages"
    for name, version, metadata in (
        ("probe", "1.0.0", _PROBE),
        ("probe_dep", "2.0.0", _PROBE_DEP),
    ):
        dist_info = root / f"{name}-{version}.dist-info"
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(metadata, encoding="utf-8")
        (dist_info / "RECORD").write_text("", encoding="utf-8")
    return root


class TestPathTarget:
    """The ``--path`` case: metadata directories named outright."""

    def test_finds_a_package_the_running_interpreter_cannot_see(
        self, site_packages: Path
    ) -> None:
        """The isolated-tool case: the package is not in peta's own environment."""
        with pytest.raises(PackageNotFoundError):
            get_package("probe")

        target = LocalTarget.create(None, (str(site_packages),))
        found = get_package("probe", target=target)
        assert found.name == "probe"
        assert found.version == "1.0.0"
        assert found.source == "local"

    def test_cli_reports_the_path_target_in_json(self, site_packages: Path) -> None:
        result = runner.invoke(
            app, ["info", "probe", "--local", "--path", str(site_packages), "--json"]
        )
        assert result.exit_code == 0
        envelope = json.loads(result.output)
        assert envelope["result"]["version"] == "1.0.0"
        environment = envelope["query"]["target_environment"]
        assert environment["paths"] == [str(site_packages)]
        assert environment["interpreter"] is None
        # With --path alone the markers are the running interpreter's, and the
        # envelope has to say so rather than leave the reader guessing.
        assert environment["markers"]["python_full_version"] == (
            ".".join(str(part) for part in sys.version_info[:3])
        )

    def test_cli_files_reads_the_path_target(self, site_packages: Path) -> None:
        result = runner.invoke(
            app, ["files", "probe", "--path", str(site_packages), "--json"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output)["result"]["name"] == "probe"


class TestTargetMarkers:
    """Markers must come from the selected target, not the running runtime."""

    def test_dependency_kept_when_the_target_satisfies_the_marker(
        self, site_packages: Path
    ) -> None:
        target = LocalTarget(
            paths=(str(site_packages),),
            interpreter="/somewhere/python3.13",
            marker_environment=_markers(),
        )
        tree = build_tree("probe", local=True, remote=False, target=target)
        assert [child.name for child in tree.children] == ["probe-dep"]
        assert tree.children[0].installed_version == "2.0.0"

    def test_dependency_dropped_when_the_target_does_not(
        self, site_packages: Path
    ) -> None:
        """Same tree, same runtime, different target: the marker decides."""
        target = LocalTarget(
            paths=(str(site_packages),),
            interpreter="/somewhere/python3.14",
            marker_environment=_markers(
                python_version="3.14", python_full_version="3.14.7"
            ),
        )
        tree = build_tree("probe", local=True, remote=False, target=target)
        assert tree.children == []


class TestPrecedence:
    """Both options at once: paths from ``--path``, markers from ``--python``."""

    def test_paths_come_from_path_and_markers_from_python(
        self, site_packages: Path
    ) -> None:
        payload = json.dumps({
            "paths": ["/the/interpreters/own/site-packages"],
            "marker_environment": _markers(),
        })
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload)
        with patch("peta.core.local.subprocess.run", return_value=completed):
            target = LocalTarget.create(sys.executable, (str(site_packages),))

        assert target.paths == (str(site_packages),)
        assert target.interpreter == sys.executable
        assert target.marker_environment == _markers()
        # The inspected package therefore comes from --path, while the marker
        # that decides its dependency comes from --python.
        tree = build_tree("probe", local=True, remote=False, target=target)
        assert [child.name for child in tree.children] == ["probe-dep"]

    def test_python_alone_uses_the_interpreters_own_paths(self) -> None:
        payload = json.dumps({
            "paths": ["/the/interpreters/own/site-packages"],
            "marker_environment": _markers(),
        })
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload)
        with patch("peta.core.local.subprocess.run", return_value=completed):
            target = LocalTarget.create(sys.executable)

        assert target.paths == ("/the/interpreters/own/site-packages",)


class TestInvalidTargets:
    """Every rejected target must be actionable and exit 2."""

    @pytest.mark.parametrize(
        ("option", "value", "expected"),
        [
            pytest.param(
                "--python", "/no/such/python", "file does not exist", id="missing-exe"
            ),
            pytest.param(
                "--path", "/no/such/dir", "expected an existing directory", id="bad-dir"
            ),
        ],
    )
    def test_cli_rejects(self, option: str, value: str, expected: str) -> None:
        result = runner.invoke(app, ["info", "probe", option, value])
        assert result.exit_code == 2
        assert expected in result.output

    def test_a_file_that_is_not_an_interpreter(self, tmp_path: Path) -> None:
        not_python = tmp_path / "not-python"
        not_python.write_text("", encoding="utf-8")
        result = runner.invoke(app, ["info", "probe", "--python", str(not_python)])
        assert result.exit_code == 2
        assert "could not inspect it" in result.output
