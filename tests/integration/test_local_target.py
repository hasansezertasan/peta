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
        assert tree.children[0].selected_version == "2.0.0"

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


class TestBlankTargets:
    """An explicitly empty option must be rejected, never silently ignored."""

    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param(["info", "probe", "--local"], id="info"),
            pytest.param(["compare", "probe", "probe-dep", "--local"], id="compare"),
            pytest.param(["deps", "probe", "--local"], id="deps"),
            pytest.param(["files", "probe"], id="files"),
        ],
    )
    def test_empty_python_does_not_fall_back_to_the_running_environment(
        self, argv: list[str]
    ) -> None:
        """``--python ""`` (an unset shell variable) must not retarget the query."""
        result = runner.invoke(app, [*argv, "--python", ""])
        assert result.exit_code == 2
        assert "no interpreter path given" in result.output

    def test_empty_path_is_not_the_working_directory(self) -> None:
        """``Path("").resolve()`` is the cwd, so an empty --path must be rejected."""
        result = runner.invoke(app, ["info", "probe", "--local", "--path", ""])
        assert result.exit_code == 2
        assert "expected an existing directory" in result.output


class TestArgumentsMapping:
    """``query.arguments`` records the invocation, nothing else."""

    def test_target_environment_is_not_duplicated_into_arguments(
        self, site_packages: Path
    ) -> None:
        result = runner.invoke(
            app, ["info", "probe", "--local", "--path", str(site_packages), "--json"]
        )
        query = json.loads(result.output)["query"]
        assert "target_environment" not in query["arguments"]
        assert query["arguments"]["paths"] == [str(site_packages)]
        # The environment is still published, once, in its documented place.
        assert query["target_environment"]["paths"] == [str(site_packages)]

    def test_absent_from_arguments_on_an_error_envelope_too(self) -> None:
        result = runner.invoke(
            app, ["info", "probe", "--json", "--path", "/no/such/dir"]
        )
        query = json.loads(result.output)["query"]
        assert "target_environment" not in query["arguments"]
        assert query["arguments"]["paths"] == ["/no/such/dir"]


# Metadata as the tools of older target environments left it on disk: the
# pre-PEP 345 formats, PEP 345 itself (parenthesized version specifiers), and
# the setuptools ``.egg-info`` layout that predates wheels, whose dependencies
# live in ``requires.txt`` rather than in the metadata file.
_LEGACY_DIST_INFO = {
    "pep241-1.0.dist-info": """\
Metadata-Version: 1.0
Name: pep241
Version: 1.0
Summary: Metadata-Version 1.0.
Home-page: https://example.invalid/pep241
License: BSD
""",
    "pep314-1.1.dist-info": """\
Metadata-Version: 1.1
Name: pep314
Version: 1.1
Summary: Metadata-Version 1.1.
Classifier: Programming Language :: Python :: 2.7
Requires: ancient
""",
    "pep345-1.2.dist-info": """\
Metadata-Version: 1.2
Name: pep345
Version: 1.2
Summary: Metadata-Version 1.2.
Requires-Python: >=2.7, !=3.0.*
Requires-Dist: probe-dep (>=2.0)
Project-URL: Source, https://example.invalid/pep345
""",
}


@pytest.fixture
def legacy_site_packages(site_packages: Path) -> Path:
    """Add old-format distributions beside the modern ``probe`` pair.

    Returns:
        The same ``--path`` target, now also holding the legacy layouts.
    """
    for directory, metadata in _LEGACY_DIST_INFO.items():
        dist_info = site_packages / directory
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(metadata, encoding="utf-8")
    egg_info = site_packages / "legacy_egg-0.4-py2.7.egg-info"
    egg_info.mkdir()
    (egg_info / "PKG-INFO").write_text(
        "Metadata-Version: 1.1\nName: legacy-egg\nVersion: 0.4\n"
        "Summary: setuptools egg-info.\nLicense: MIT\n",
        encoding="utf-8",
    )
    (egg_info / "requires.txt").write_text(
        "probe-dep\n\n[docs]\nsphinx\n", encoding="utf-8"
    )
    return site_packages


class TestOlderTargetMetadata:
    """Metadata written by an older target environment's tools reads cleanly.

    The ``--path`` target is what an isolated modern peta points at an older
    project environment, so the formats that environment's installers wrote
    must be read as they are, not only the ones current tools write.
    """

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param(
                "pep241",
                {
                    "version": "1.0",
                    "homepage": "https://example.invalid/pep241",
                    "license": "BSD",
                    "license_source": "legacy",
                    "dependencies": [],
                },
                id="metadata-1.0",
            ),
            pytest.param(
                "pep314",
                {
                    "version": "1.1",
                    "classifiers": ["Programming Language :: Python :: 2.7"],
                    # ``Requires`` names modules, not distributions, and no
                    # installer ever resolved it; it is not a dependency.
                    "dependencies": [],
                },
                id="metadata-1.1",
            ),
            pytest.param(
                "pep345",
                {
                    "version": "1.2",
                    "python_requires": ">=2.7, !=3.0.*",
                    "dependencies": ["probe-dep (>=2.0)"],
                    "project_urls": {"Source": "https://example.invalid/pep345"},
                },
                id="metadata-1.2",
            ),
            pytest.param(
                "legacy-egg",
                {
                    "version": "0.4",
                    "license": "MIT",
                    "dependencies": ["probe-dep", 'sphinx; extra == "docs"'],
                },
                id="egg-info",
            ),
        ],
    )
    def test_reads_the_legacy_layout(
        self, legacy_site_packages: Path, name: str, expected: dict[str, object]
    ) -> None:
        target = LocalTarget.create(None, (str(legacy_site_packages),))
        found = get_package(name, target=target)
        assert found.source == "local"
        for field, value in expected.items():
            assert getattr(found, field) == value, field

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("pep345", id="parenthesized-specifier"),
            pytest.param("legacy-egg", id="requires-txt"),
        ],
    )
    def test_legacy_dependencies_resolve_in_the_tree(
        self, legacy_site_packages: Path, name: str
    ) -> None:
        """Both old spellings reach ``probe-dep``; the unrequested extra does not."""
        target = LocalTarget.create(None, (str(legacy_site_packages),))
        tree = build_tree(name, local=True, remote=False, target=target)
        assert [child.name for child in tree.children] == ["probe-dep"]
        assert tree.children[0].selected_version == "2.0.0"

    @pytest.mark.parametrize(
        ("listing", "expected"),
        [
            pytest.param(
                "../installed_egg/__init__.py\n\nPKG-INFO\n",
                ["installed_egg/__init__.py", "installed_egg-1.0.egg-info/PKG-INFO"],
                id="installed-files",
            ),
            pytest.param(
                "../installed_egg/gone.py\n", None, id="every-listed-file-gone"
            ),
        ],
    )
    def test_egg_info_files_are_what_was_installed(
        self, site_packages: Path, listing: str, expected: list[str] | None
    ) -> None:
        """``installed-files.txt``, never ``SOURCES.txt``, on every Python.

        Python 3.11's importlib.metadata skips ``installed-files.txt`` and
        reports the source tree instead; peta must not inherit that.
        """
        package = site_packages / "installed_egg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        egg_info = site_packages / "installed_egg-1.0.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text(
            "Metadata-Version: 1.1\nName: installed-egg\nVersion: 1.0\n",
            encoding="utf-8",
        )
        (egg_info / "SOURCES.txt").write_text(
            "setup.py\ninstalled_egg/__init__.py\n", encoding="utf-8"
        )
        (egg_info / "installed-files.txt").write_text(listing, encoding="utf-8")
        target = LocalTarget.create(None, (str(site_packages),))
        assert get_package("installed-egg", target=target).files == expected

    def test_cli_renders_the_oldest_format(self, legacy_site_packages: Path) -> None:
        result = runner.invoke(
            app,
            [
                "info",
                "pep241",
                "--local",
                "--no-osv",
                "--no-stats",
                "--path",
                str(legacy_site_packages),
                "--json",
            ],
        )
        assert result.exit_code == 0
        assert json.loads(result.output)["result"]["version"] == "1.0"
