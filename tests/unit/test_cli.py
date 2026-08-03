"""Unit tests for the CLI (core layer mocked)."""

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import _SUBCOMMANDS, app
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import PackageInfo, Vulnerability
from peta.core.remote import PackageNotFoundError as RemoteNotFound

pytestmark = pytest.mark.unit
runner = CliRunner()


def _pkg(**over: object) -> PackageInfo:
    base: dict[str, object] = {
        "name": "requests",
        "version": "2.31.0",
        "source": "local",
        "summary": "Python HTTP for Humans.",
        "dependencies": ["urllib3"],
        "files": None,
        "vulnerabilities": [],
    }
    base.update(over)
    return PackageInfo(**base)  # type: ignore[arg-type]


class TestInfo:
    @patch("peta.cli.commands.info.local_get_package")
    def test_local(self, m: object) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output

    @patch("peta.cli.commands.info.remote_get_package")
    @patch("peta.cli.commands.info.local_get_package")
    def test_fallback_to_remote(self, ml: object, mr: object) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "x"]).exit_code == 0

    @patch("peta.cli.commands.info.remote_get_package")
    def test_version_specifier(self, mr: object) -> None:
        mr.return_value = _pkg(version="2.28.0", source="remote")
        r = runner.invoke(app, ["info", "requests==2.28.0"])
        assert r.exit_code == 0
        mr.assert_called_once_with("requests", "2.28.0")

    @patch("peta.cli.commands.info.local_get_package")
    def test_json(self, m: object) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json"])
        assert json.loads(r.output)["name"] == "requests"

    @patch("peta.cli.commands.info.remote_get_package")
    def test_remote_flag(self, mr: object) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "requests", "-r"]).exit_code == 0
        mr.assert_called_once()

    @patch("peta.cli.commands.info.local_get_package")
    def test_local_flag(self, ml: object) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["info", "requests", "-l"]).exit_code == 0
        ml.assert_called_once()

    @patch("peta.cli.commands.info.local_get_package")
    def test_shows_vuln(self, ml: object) -> None:
        v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["2.32.0"])
        ml.return_value = _pkg(vulnerabilities=[v])
        assert "PYSEC-1" in runner.invoke(app, ["info", "requests"]).output

    @patch("peta.cli.commands.info.remote_get_package")
    @patch("peta.cli.commands.info.local_get_package")
    def test_not_found(self, ml: object, mr: object) -> None:
        ml.side_effect = LocalNotFound("n")
        mr.side_effect = RemoteNotFound("n")
        assert runner.invoke(app, ["info", "n"]).exit_code == 1

    @patch("peta.cli.commands.info.remote_get_package")
    def test_network_error_exit_2(self, mr: object) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["info", "x", "-r"]).exit_code == 2


class TestDeps:
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps(self, m: object) -> None:
        m.return_value = _pkg()
        assert "urllib3" in runner.invoke(app, ["deps", "requests"]).output

    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_json(self, m: object) -> None:
        m.return_value = _pkg()
        assert "dependencies" in json.loads(
            runner.invoke(app, ["deps", "requests", "--json"]).output
        )

    @patch("peta.cli.commands.deps.remote_get_package")
    def test_deps_remote_flag(self, mr: object) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "requests", "-r"]).exit_code == 0
        mr.assert_called_once()

    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_local_flag(self, ml: object) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["deps", "requests", "-l"]).exit_code == 0
        ml.assert_called_once()

    @patch("peta.cli.commands.deps.remote_get_package")
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_fallback_to_remote(self, ml: object, mr: object) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 0

    @patch("peta.cli.commands.deps.remote_get_package")
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_not_found(self, ml: object, mr: object) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.side_effect = RemoteNotFound("x")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 1

    @patch("peta.cli.commands.deps.remote_get_package")
    def test_deps_network_error_exit_2(self, mr: object) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["deps", "x", "-r"]).exit_code == 2


class TestFiles:
    @patch("peta.cli.commands.files.local_get_package")
    def test_files(self, m: object) -> None:
        m.return_value = _pkg(files=["requests/__init__.py"])
        assert "__init__.py" in runner.invoke(app, ["files", "requests"]).output

    @patch("peta.cli.commands.files.local_get_package")
    def test_files_not_found(self, m: object) -> None:
        m.side_effect = LocalNotFound("x")
        assert runner.invoke(app, ["files", "x"]).exit_code == 1

    @patch("peta.cli.commands.files.local_get_package")
    def test_files_json(self, m: object) -> None:
        m.return_value = _pkg(files=["a.py"])
        assert "files" in json.loads(
            runner.invoke(app, ["files", "requests", "--json"]).output
        )


class TestVersions:
    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions(self, m: object) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert "2.31.0" in runner.invoke(app, ["versions", "requests"]).output

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_json(self, m: object) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert isinstance(
            json.loads(runner.invoke(app, ["versions", "requests", "--json"]).output)[
                "versions"
            ],
            list,
        )

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_not_found(self, m: object) -> None:
        m.return_value = []
        assert runner.invoke(app, ["versions", "nope"]).exit_code == 1

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_limit(self, m: object) -> None:
        m.return_value = [
            {"version": f"1.{i}.0", "upload_time": ""} for i in range(4, -1, -1)
        ]
        out = runner.invoke(app, ["versions", "x", "-n", "2"]).output
        assert "1.4.0" in out
        assert "1.2.0" not in out

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_network_error_exit_2(self, m: object) -> None:
        from peta.core.remote import NetworkError

        m.side_effect = NetworkError("down")
        assert runner.invoke(app, ["versions", "x"]).exit_code == 2


class TestRun:
    def test_shorthand_inserts_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import peta.cli.app as app_mod

        monkeypatch.setattr("sys.argv", ["peta", "requests"])
        monkeypatch.setattr(app_mod, "app", lambda: None)
        app_mod.run()
        import sys

        assert sys.argv[:2] == ["peta", "info"]

    def test_subcommand_not_rewritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import peta.cli.app as app_mod

        monkeypatch.setattr("sys.argv", ["peta", "info", "requests"])
        monkeypatch.setattr(app_mod, "app", lambda: None)
        app_mod.run()
        import sys

        assert sys.argv == ["peta", "info", "requests"]

    def test_flag_not_rewritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import peta.cli.app as app_mod

        monkeypatch.setattr("sys.argv", ["peta", "--version"])
        monkeypatch.setattr(app_mod, "app", lambda: None)
        app_mod.run()
        import sys

        assert sys.argv == ["peta", "--version"]

    def test_dunder_main_entrypoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        monkeypatch.setattr("sys.argv", ["peta", "--help"])
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("peta", run_name="__main__")
        assert exc.value.code == 0


class TestRoot:
    def test_help(self) -> None:
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0
        assert "peta" in r.output.lower()

    def test_version_flag(self) -> None:
        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 0
        assert r.output.strip().startswith("peta ")

    def test_subcommands_registry(self) -> None:
        assert "info" in _SUBCOMMANDS
        assert "requests" not in _SUBCOMMANDS
