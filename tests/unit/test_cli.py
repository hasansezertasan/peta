"""Unit tests for the CLI (core layer mocked)."""

import json
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import _SUBCOMMANDS, app, run
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import PackageInfo, Vulnerability
from peta.core.remote import PackageNotFoundError as RemoteNotFound

pytestmark = pytest.mark.unit
runner = CliRunner()


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="requests",
        version="2.31.0",
        source="local",
        summary="Python HTTP for Humans.",
        dependencies=["urllib3"],
        files=None,
        vulnerabilities=[],
    )
    return replace(base, **over)


class TestInfo:
    @patch("peta.cli.commands.info.local_get_package")
    def test_local(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output

    @patch("peta.cli.commands.info.remote_get_package")
    @patch("peta.cli.commands.info.local_get_package")
    def test_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "x"]).exit_code == 0

    @patch("peta.cli.commands.info.remote_get_package")
    def test_version_specifier(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(version="2.28.0", source="remote")
        r = runner.invoke(app, ["info", "requests==2.28.0"])
        assert r.exit_code == 0
        mr.assert_called_once_with("requests", "2.28.0")

    @patch("peta.cli.commands.info.local_get_package")
    def test_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json"])
        assert json.loads(r.output)["name"] == "requests"

    @patch("peta.cli.commands.info.remote_get_package")
    def test_remote_flag(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "requests", "-r"]).exit_code == 0
        mr.assert_called_once()

    @patch("peta.cli.commands.info.local_get_package")
    def test_local_flag(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["info", "requests", "-l"]).exit_code == 0
        ml.assert_called_once()

    @patch("peta.cli.commands.info.remote_get_package")
    def test_local_with_version_rejected(self, mr: MagicMock) -> None:
        # --local with a name==version specifier is contradictory; it must be
        # rejected, not silently fall through to a remote lookup.
        result = runner.invoke(app, ["info", "requests==2.28.0", "-l"])
        assert result.exit_code != 0
        mr.assert_not_called()

    @patch("peta.cli.commands.info.local_get_package")
    def test_shows_vuln(self, ml: MagicMock) -> None:
        v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["2.32.0"])
        ml.return_value = _pkg(vulnerabilities=[v])
        assert "PYSEC-1" in runner.invoke(app, ["info", "requests"]).output

    @patch("peta.cli.commands.info.remote_get_package")
    @patch("peta.cli.commands.info.local_get_package")
    def test_not_found(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("n")
        mr.side_effect = RemoteNotFound("n")
        assert runner.invoke(app, ["info", "n"]).exit_code == 1

    @patch("peta.cli.commands.info.remote_get_package")
    def test_network_error_exit_2(self, mr: MagicMock) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["info", "x", "-r"]).exit_code == 2

    @patch("peta.cli.commands.info.osv.get_vulnerabilities")
    @patch("peta.cli.commands.info.local_get_package")
    def test_osv_enriches_output(self, ml: MagicMock, mo: MagicMock) -> None:
        ml.return_value = _pkg()
        mo.return_value = [
            Vulnerability(id="GHSA-osv", aliases=[], summary="s", fixed_in=["9.9.9"])
        ]
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "GHSA-osv" in r.output
        mo.assert_called_once_with("requests", "2.31.0")

    @patch("peta.cli.commands.info.osv.get_vulnerabilities")
    @patch("peta.cli.commands.info.local_get_package")
    def test_osv_deduped_against_pypi_vuln_by_alias(
        self, ml: MagicMock, mo: MagicMock
    ) -> None:
        pypi_vuln = Vulnerability(
            id="PYSEC-1", aliases=["CVE-2024-1"], summary="pypi", fixed_in=["1.0"]
        )
        ml.return_value = _pkg(vulnerabilities=[pypi_vuln])
        mo.return_value = [
            Vulnerability(
                id="GHSA-2",
                aliases=["CVE-2024-1"],
                summary="osv",
                fixed_in=["1.1"],
                severity="HIGH",
            )
        ]
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        # Same identity (shared alias) collapses to a single entry; "GHSA-2"
        # must not appear as a second, separate vulnerability.
        assert r.output.count("PYSEC-1") == 1
        assert "GHSA-2" not in r.output
        assert "[HIGH]" in r.output

    @patch("peta.cli.commands.info.osv.get_vulnerabilities")
    @patch("peta.cli.commands.info.local_get_package")
    def test_no_osv_skips_lookup(self, ml: MagicMock, mo: MagicMock) -> None:
        ml.return_value = _pkg()
        mo.return_value = [
            Vulnerability(id="GHSA-osv", aliases=[], summary="s", fixed_in=["9.9.9"])
        ]
        r = runner.invoke(app, ["info", "requests", "--no-osv"])
        assert r.exit_code == 0
        mo.assert_not_called()
        assert "GHSA-osv" not in r.output

    @patch("peta.cli.commands.info.stats.libraries_io_api_key")
    @patch("peta.cli.commands.info.stats.get_dependent_count")
    @patch("peta.cli.commands.info.stats.get_download_count")
    @patch("peta.cli.commands.info.local_get_package")
    def test_stats_enrich_output(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        mdl.return_value = 1234567
        mdep.return_value = 42
        mkey.return_value = "secret"
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "1,234,567" in r.output
        assert "42" in r.output
        mdep.assert_called_once_with("requests", api_key="secret")

    @patch("peta.cli.commands.info.stats.get_dependent_count")
    @patch("peta.cli.commands.info.stats.get_download_count")
    @patch("peta.cli.commands.info.local_get_package")
    def test_no_stats_skips_lookup(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--no-stats"])
        assert r.exit_code == 0
        mdl.assert_not_called()
        mdep.assert_not_called()
        assert "Downloads" not in r.output
        assert "Dependents" not in r.output

    @patch("peta.cli.commands.info.stats.libraries_io_api_key")
    @patch("peta.cli.commands.info.stats.get_dependent_count")
    @patch("peta.cli.commands.info.stats.get_download_count")
    @patch("peta.cli.commands.info.local_get_package")
    def test_stats_in_json(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        mdl.return_value = 100
        mdep.return_value = 5
        mkey.return_value = None
        r = runner.invoke(app, ["info", "requests", "--json"])
        data = json.loads(r.output)
        assert data["download_count"] == 100
        assert data["dependent_count"] == 5


class TestDeps:
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        assert "urllib3" in runner.invoke(app, ["deps", "requests"]).output

    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        assert "dependencies" in json.loads(
            runner.invoke(app, ["deps", "requests", "--json"]).output
        )

    @patch("peta.cli.commands.deps.remote_get_package")
    def test_deps_remote_flag(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "requests", "-r"]).exit_code == 0
        mr.assert_called_once()

    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_local_flag(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["deps", "requests", "-l"]).exit_code == 0
        ml.assert_called_once()

    @patch("peta.cli.commands.deps.remote_get_package")
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 0

    @patch("peta.cli.commands.deps.remote_get_package")
    @patch("peta.cli.commands.deps.local_get_package")
    def test_deps_not_found(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.side_effect = RemoteNotFound("x")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 1

    @patch("peta.cli.commands.deps.remote_get_package")
    def test_deps_network_error_exit_2(self, mr: MagicMock) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["deps", "x", "-r"]).exit_code == 2


class TestFiles:
    @patch("peta.cli.commands.files.local_get_package")
    def test_files(self, m: MagicMock) -> None:
        m.return_value = _pkg(files=["requests/__init__.py"])
        assert "__init__.py" in runner.invoke(app, ["files", "requests"]).output

    @patch("peta.cli.commands.files.local_get_package")
    def test_files_not_found(self, m: MagicMock) -> None:
        m.side_effect = LocalNotFound("x")
        assert runner.invoke(app, ["files", "x"]).exit_code == 1

    @patch("peta.cli.commands.files.local_get_package")
    def test_files_json(self, m: MagicMock) -> None:
        m.return_value = _pkg(files=["a.py"])
        assert "files" in json.loads(
            runner.invoke(app, ["files", "requests", "--json"]).output
        )


class TestVersions:
    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions(self, m: MagicMock) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert "2.31.0" in runner.invoke(app, ["versions", "requests"]).output

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_json(self, m: MagicMock) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert isinstance(
            json.loads(runner.invoke(app, ["versions", "requests", "--json"]).output)[
                "versions"
            ],
            list,
        )

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_not_found(self, m: MagicMock) -> None:
        m.return_value = []
        assert runner.invoke(app, ["versions", "nope"]).exit_code == 1

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_limit(self, m: MagicMock) -> None:
        m.return_value = [
            {"version": f"1.{i}.0", "upload_time": ""} for i in range(4, -1, -1)
        ]
        out = runner.invoke(app, ["versions", "x", "-n", "2"]).output
        assert "1.4.0" in out
        assert "1.2.0" not in out

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_network_error_exit_2(self, m: MagicMock) -> None:
        from peta.core.remote import NetworkError

        m.side_effect = NetworkError("down")
        assert runner.invoke(app, ["versions", "x"]).exit_code == 2

    def test_versions_negative_limit_rejected(self) -> None:
        # A negative --limit must be rejected by Typer, not become a reverse
        # slice (vers[:-1]) that prints all-but-last.
        result = runner.invoke(app, ["versions", "requests", "-n", "-1"])
        assert result.exit_code != 0


class TestRun:
    def test_shorthand_inserts_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["peta", "requests"])
        monkeypatch.setattr("peta.cli.app.app", lambda: None)
        run()
        import sys

        assert sys.argv[:2] == ["peta", "info"]

    def test_subcommand_not_rewritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["peta", "info", "requests"])
        monkeypatch.setattr("peta.cli.app.app", lambda: None)
        run()
        import sys

        assert sys.argv == ["peta", "info", "requests"]

    def test_flag_not_rewritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["peta", "--version"])
        monkeypatch.setattr("peta.cli.app.app", lambda: None)
        run()
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

    def test_dash_h_shows_help(self) -> None:
        # -h is advertised in _SUBCOMMANDS; it must actually render help.
        r = runner.invoke(app, ["-h"])
        assert r.exit_code == 0
        assert "peta" in r.output.lower()

    def test_version_flag(self) -> None:
        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 0
        assert r.output.strip().startswith("peta ")

    def test_subcommands_registry(self) -> None:
        assert "info" in _SUBCOMMANDS
        assert "requests" not in _SUBCOMMANDS


class TestNoColor:
    @patch("peta.cli.commands.info.local_get_package")
    def test_no_color_flag_still_plain(self, m: MagicMock) -> None:
        # CliRunner output is already non-TTY, but --no-color must not break
        # anything and must still print the package plainly.
        m.return_value = _pkg()
        r = runner.invoke(app, ["--no-color", "info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output
        assert "\x1b" not in r.output

    @patch("peta.cli.commands.info.local_get_package")
    def test_no_color_env_var(
        self, m: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output
        assert "\x1b" not in r.output
