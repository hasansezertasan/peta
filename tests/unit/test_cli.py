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
    @patch("peta.core.resolve.local_get_package")
    def test_local(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "x"]).exit_code == 0

    @patch("peta.core.resolve.remote_get_package")
    def test_version_specifier(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(version="2.28.0", source="remote")
        r = runner.invoke(app, ["info", "requests==2.28.0"])
        assert r.exit_code == 0
        mr.assert_called_once_with("requests", "2.28.0")

    @patch("peta.core.resolve.local_get_package")
    def test_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json"])
        data = json.loads(r.output)
        assert data["schema_version"] == "1"
        assert data["result"]["name"] == "requests"

    @patch("peta.core.resolve.local_get_package")
    def test_format_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--format", "json"])
        assert r.exit_code == 0
        assert json.loads(r.output)["query"]["command"] == "info"

    @patch("peta.core.resolve.local_get_package")
    def test_format_markdown(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--format", "markdown"])
        assert r.exit_code == 0
        assert r.output.startswith("# requests 2.31.0")

    @patch("peta.core.resolve.local_get_package")
    def test_format_text_is_plain(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--format", "text"])
        assert r.exit_code == 0
        assert r.output.startswith("Name: requests\nVersion: 2.31.0")
        assert "┏" not in r.output

    def test_json_error_is_structured(self) -> None:
        with (
            patch("peta.core.resolve.local_get_package") as ml,
            patch("peta.core.resolve.remote_get_package") as mr,
        ):
            ml.side_effect = LocalNotFound("missing")
            mr.side_effect = RemoteNotFound("missing")
            r = runner.invoke(app, ["info", "missing", "--format", "json"])
        assert r.exit_code == 1
        data = json.loads(r.output)
        assert data["status"] == "failed"
        assert data["errors"][0]["code"] == "package_not_found"

    @patch("peta.core.resolve.remote_get_package")
    def test_remote_flag(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["info", "requests", "-r"]).exit_code == 0
        mr.assert_called_once()

    @patch("peta.core.resolve.local_get_package")
    def test_local_flag(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["info", "requests", "-l"]).exit_code == 0
        ml.assert_called_once()

    @patch("peta.core.resolve.remote_get_package")
    def test_local_with_version_rejected(self, mr: MagicMock) -> None:
        # --local with a name==version specifier is contradictory; it must be
        # rejected, not silently fall through to a remote lookup.
        result = runner.invoke(app, ["info", "requests==2.28.0", "-l"])
        assert result.exit_code != 0
        mr.assert_not_called()

    @patch("peta.core.resolve.local_get_package")
    def test_shows_vuln(self, ml: MagicMock) -> None:
        v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["2.32.0"])
        ml.return_value = _pkg(vulnerabilities=[v])
        assert "PYSEC-1" in runner.invoke(app, ["info", "requests"]).output

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_not_found(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("n")
        mr.side_effect = RemoteNotFound("n")
        assert runner.invoke(app, ["info", "n"]).exit_code == 1

    @patch("peta.core.resolve.remote_get_package")
    def test_network_error_exit_2(self, mr: MagicMock) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["info", "x", "-r"]).exit_code == 2

    @patch("peta.core.enrich.osv.get_vulnerabilities")
    @patch("peta.core.resolve.local_get_package")
    def test_osv_enriches_output(self, ml: MagicMock, mo: MagicMock) -> None:
        ml.return_value = _pkg()
        mo.return_value = [
            Vulnerability(id="GHSA-osv", aliases=[], summary="s", fixed_in=["9.9.9"])
        ]
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "GHSA-osv" in r.output
        mo.assert_called_once_with("requests", "2.31.0")

    @patch("peta.core.enrich.osv.get_vulnerabilities")
    @patch("peta.core.resolve.local_get_package")
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

    @patch("peta.core.enrich.osv.get_vulnerabilities")
    @patch("peta.core.resolve.local_get_package")
    def test_no_osv_skips_lookup(self, ml: MagicMock, mo: MagicMock) -> None:
        ml.return_value = _pkg()
        mo.return_value = [
            Vulnerability(id="GHSA-osv", aliases=[], summary="s", fixed_in=["9.9.9"])
        ]
        r = runner.invoke(app, ["info", "requests", "--no-osv"])
        assert r.exit_code == 0
        mo.assert_not_called()
        assert "GHSA-osv" not in r.output

    @patch("peta.core.enrich.stats.libraries_io_api_key")
    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    @patch("peta.core.resolve.local_get_package")
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

    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    @patch("peta.core.resolve.local_get_package")
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

    @patch("peta.core.enrich.stats.libraries_io_api_key")
    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    @patch("peta.core.resolve.local_get_package")
    def test_stats_in_json(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        mdl.return_value = 100
        mdep.return_value = 5
        mkey.return_value = "secret"
        r = runner.invoke(app, ["info", "requests", "--json"])
        data = json.loads(r.output)
        assert data["result"]["download_count"] == 100
        assert data["result"]["dependent_count"] == 5


class TestOutputContract:
    def test_json_invalid_package_is_structured(self) -> None:
        r = runner.invoke(app, ["info", "==", "--format", "json"])
        assert r.exit_code == 2
        data = json.loads(r.output)
        assert data["schema_version"] == "1"
        assert data["errors"][0]["code"] == "invalid_arguments"

    def test_conflicting_json_formats_are_structured(self) -> None:
        r = runner.invoke(app, ["info", "requests", "--json", "--format", "markdown"])
        assert r.exit_code == 2
        data = json.loads(r.output)
        assert data["status"] == "failed"
        assert data["errors"][0]["code"] == "invalid_arguments"

    @pytest.mark.parametrize(
        "arguments",
        [
            ["deps", "requests", "--depth", "0", "--format", "json"],
            ["versions", "requests", "--limit", "0", "--format", "json"],
            ["info", "--format", "json"],
            ["info", "requests", "--unknown", "--format", "json"],
            ["deps", "requests", "--depth", "0", "--format", "JSON"],
            ["versions", "requests", "--limit=0", "--format=JSON"],
        ],
    )
    def test_parser_validation_errors_are_structured(
        self, arguments: list[str]
    ) -> None:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert data["schema_version"] == "1"
        assert data["status"] == "failed"
        assert data["errors"][0]["code"] == "invalid_arguments"


class TestCompare:
    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_table(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = [_pkg(), LocalNotFound("httpx")]
        mr.return_value = _pkg(name="httpx", version="0.27.0", source="remote")
        r = runner.invoke(app, ["compare", "requests", "httpx"])
        assert r.exit_code == 0
        assert "requests" in r.output
        assert "httpx" in r.output
        assert "2.31.0" in r.output
        assert "0.27.0" in r.output

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_json(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = [_pkg(), LocalNotFound("httpx")]
        mr.return_value = _pkg(name="httpx", version="0.27.0", source="remote")
        r = runner.invoke(app, ["compare", "requests", "httpx", "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert len(data["result"]["packages"]) == 2
        assert data["result"]["packages"][0]["name"] == "requests"
        assert data["result"]["packages"][1]["name"] == "httpx"

    @patch("peta.core.resolve.local_get_package")
    def test_compare_markdown(self, ml: MagicMock) -> None:
        ml.side_effect = [_pkg(), _pkg(name="httpx", version="0.27.0")]
        result = runner.invoke(
            app, ["compare", "requests", "httpx", "--format", "markdown"]
        )
        assert result.exit_code == 0
        assert result.output.startswith("# Package comparison")

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_not_found_in_first(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("nope")
        mr.side_effect = RemoteNotFound("nope")
        r = runner.invoke(app, ["compare", "nope", "httpx"])
        assert r.exit_code == 1
        # Message names the failed package cleanly (no double-wrapped exception).
        assert "Package 'nope' not found." in r.output
        assert "not found on PyPI" not in r.output

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_not_found_in_second(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = [_pkg(), LocalNotFound("nope")]
        mr.side_effect = RemoteNotFound("nope")
        r = runner.invoke(app, ["compare", "requests", "nope"])
        assert r.exit_code == 1

    @patch("peta.core.resolve.remote_get_package")
    def test_compare_not_found_with_version_shows_version(self, mr: MagicMock) -> None:
        mr.side_effect = RemoteNotFound("nope", "9.9.9")
        r = runner.invoke(app, ["compare", "nope==9.9.9", "requests"])
        assert r.exit_code == 1
        assert "Package 'nope==9.9.9' not found." in r.output

    @patch("peta.core.resolve.remote_get_package")
    def test_compare_network_error_exit_2(self, mr: MagicMock) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        r = runner.invoke(app, ["compare", "a", "b", "-r"])
        assert r.exit_code == 2

    @patch("peta.core.enrich.osv.get_vulnerabilities")
    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_no_osv_skips_lookup(
        self, ml: MagicMock, mr: MagicMock, mo: MagicMock
    ) -> None:
        ml.side_effect = [_pkg(), LocalNotFound("httpx")]
        mr.return_value = _pkg(name="httpx", version="0.27.0", source="remote")
        r = runner.invoke(app, ["compare", "requests", "httpx", "--no-osv"])
        assert r.exit_code == 0
        mo.assert_not_called()

    @patch("peta.core.enrich.stats.get_dependent_count")
    @patch("peta.core.enrich.stats.get_download_count")
    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_compare_no_stats_skips_lookup(
        self, ml: MagicMock, mr: MagicMock, mdl: MagicMock, mdep: MagicMock
    ) -> None:
        ml.side_effect = [_pkg(), LocalNotFound("httpx")]
        mr.return_value = _pkg(name="httpx", version="0.27.0", source="remote")
        r = runner.invoke(app, ["compare", "requests", "httpx", "--no-stats"])
        assert r.exit_code == 0
        mdl.assert_not_called()
        mdep.assert_not_called()


class TestDeps:
    @patch("peta.core.resolve.local_get_package")
    def test_deps(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        assert "urllib3" in runner.invoke(app, ["deps", "requests"]).output

    @patch("peta.core.resolve.local_get_package")
    def test_deps_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        data = json.loads(runner.invoke(app, ["deps", "requests", "--json"]).output)
        assert data["result"]["name"] == "requests"
        assert data["result"]["children"][0]["name"] == "urllib3"

    @patch("peta.core.resolve.local_get_package")
    def test_deps_markdown(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        result = runner.invoke(app, ["deps", "requests", "--format", "markdown"])
        assert result.output.startswith("# Dependencies for requests")

    @patch("peta.core.resolve.remote_get_package")
    def test_deps_remote_flag(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "requests", "-r"]).exit_code == 0
        assert mr.call_args_list[0].args == ("requests",)

    @patch("peta.core.resolve.local_get_package")
    def test_deps_local_flag(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["deps", "requests", "-l"]).exit_code == 0
        assert ml.call_args_list[0].args == ("requests",)

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_deps_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 0

    @patch("peta.core.resolve.remote_get_package")
    @patch("peta.core.resolve.local_get_package")
    def test_deps_not_found(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.side_effect = RemoteNotFound("x")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 1

    @patch("peta.core.resolve.remote_get_package")
    def test_deps_network_error_exit_2(self, mr: MagicMock) -> None:
        from peta.core.remote import NetworkError

        mr.side_effect = NetworkError("down")
        assert runner.invoke(app, ["deps", "x", "-r"]).exit_code == 2

    @patch("peta.core.resolve.local_get_package")
    def test_deps_why_found(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["deps", "requests", "--why", "urllib3"])
        assert r.exit_code == 0
        assert "urllib3" in r.output

    @patch("peta.core.resolve.local_get_package")
    def test_deps_why_not_found(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["deps", "requests", "--why", "nope"])
        assert r.exit_code == 1
        assert "was not found in the dependency tree of 'requests'" in r.output
        assert "depth" in r.output

    @patch("peta.core.resolve.local_get_package")
    def test_deps_why_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["deps", "requests", "--why", "urllib3", "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["result"]["target"] == "urllib3"
        assert data["result"]["paths"] == [["requests", "urllib3"]]

    @patch("peta.core.resolve.local_get_package")
    def test_deps_why_markdown(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        result = runner.invoke(
            app, ["deps", "requests", "--why", "urllib3", "--format", "markdown"]
        )
        assert result.output.startswith("# Why urllib3?")

    @patch("peta.core.resolve.local_get_package")
    def test_deps_depth_limits_recursion(self, m: MagicMock) -> None:
        pkgs = {
            "requests": _pkg(dependencies=["urllib3"]),
            "urllib3": _pkg(name="urllib3", dependencies=["brotli"]),
        }
        m.side_effect = lambda name: pkgs.get(name, _pkg(name=name, dependencies=[]))
        r = runner.invoke(app, ["deps", "requests", "--depth", "1"])
        assert r.exit_code == 0
        assert "urllib3" in r.output
        assert "brotli" not in r.output


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
        assert (
            "files"
            in json.loads(runner.invoke(app, ["files", "requests", "--json"]).output)[
                "result"
            ]
        )

    @patch("peta.cli.commands.files.local_get_package")
    def test_files_markdown(self, m: MagicMock) -> None:
        m.return_value = _pkg(files=["a.py"])
        result = runner.invoke(app, ["files", "requests", "--format", "markdown"])
        assert result.output.startswith("# Files for requests")


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
                "result"
            ]["versions"],
            list,
        )

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_markdown(self, m: MagicMock) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        result = runner.invoke(app, ["versions", "requests", "--format", "markdown"])
        assert result.output.startswith("# Versions for requests")

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

    @patch("peta.cli.app.Distribution")
    def test_version_missing_metadata_exits_1(self, mdist: MagicMock) -> None:
        from importlib.metadata import PackageNotFoundError

        mdist.from_name.side_effect = PackageNotFoundError("peta")
        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 1

    def test_subcommands_registry(self) -> None:
        assert "info" in _SUBCOMMANDS
        assert "requests" not in _SUBCOMMANDS


class TestNoColor:
    @patch("peta.core.resolve.local_get_package")
    def test_no_color_flag_still_plain(self, m: MagicMock) -> None:
        # CliRunner output is already non-TTY, but --no-color must not break
        # anything and must still print the package plainly.
        m.return_value = _pkg()
        r = runner.invoke(app, ["--no-color", "info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output
        assert "\x1b" not in r.output

    @patch("peta.core.resolve.local_get_package")
    def test_no_color_env_var(
        self, m: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "requests" in r.output
        assert "\x1b" not in r.output
