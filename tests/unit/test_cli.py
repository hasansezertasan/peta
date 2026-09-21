"""Unit tests for the CLI (core layer mocked)."""

import json
import sys
import threading
import time
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import _SUBCOMMANDS, _shorthand_position, app, run
from peta.core.artifacts import ArtifactFile, Compatibility, ReleaseArtifacts, Target
from peta.core.cache import Provenance
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import PackageInfo, Vulnerability
from peta.core.remote import PackageNotFoundError as RemoteNotFound

if TYPE_CHECKING:
    from pathlib import Path

    import httpx

    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit

_LIVE = Provenance("live", "2026-01-01T00:00:00Z")
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

    @patch("peta.core.resolve.remote_get_package_matching")
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

    def test_target_with_version_specifier_rejected(self) -> None:
        result = runner.invoke(
            app, ["info", "requests==2.28.0", "--python", sys.executable]
        )
        assert result.exit_code == 2
        assert "version specifier" in result.output

    @patch("peta.core.resolve.local_get_package")
    def test_json(self, m: MagicMock) -> None:
        m.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json"])
        data = json.loads(r.output)
        assert data["schema_version"] == "2"
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

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
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

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
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

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
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

    @patch("peta.core.providers.builtin.stats.libraries_io_api_key")
    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch("peta.core.providers.builtin.stats.get_download_count")
    @patch("peta.core.resolve.local_get_package")
    def test_stats_enrich_output(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        mdl.return_value = (1234567, _LIVE)
        mdep.return_value = (42, _LIVE)
        mkey.return_value = "secret"
        r = runner.invoke(app, ["info", "requests"])
        assert r.exit_code == 0
        assert "1,234,567" in r.output
        assert "42" in r.output
        mdep.assert_called_once_with("requests", api_key="secret")

    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch("peta.core.providers.builtin.stats.get_download_count")
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

    @patch("peta.core.providers.builtin.stats.libraries_io_api_key")
    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch("peta.core.providers.builtin.stats.get_download_count")
    @patch("peta.core.resolve.local_get_package")
    def test_stats_in_json(
        self, ml: MagicMock, mdl: MagicMock, mdep: MagicMock, mkey: MagicMock
    ) -> None:
        ml.return_value = _pkg()
        mdl.return_value = (100, _LIVE)
        mdep.return_value = (5, _LIVE)
        mkey.return_value = "secret"
        r = runner.invoke(app, ["info", "requests", "--json"])
        data = json.loads(r.output)
        assert data["result"]["download_count"] == 100
        assert data["result"]["dependent_count"] == 5


class TestEnvironmentTargeting:
    """``--python`` / ``--path`` wiring shared by info, compare, deps, files."""

    @patch("peta.core.resolve.local_get_package")
    def test_compare_forwards_the_target(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        result = runner.invoke(
            app, ["compare", "requests", "httpx", "--local", "--python", sys.executable]
        )
        assert result.exit_code == 0
        assert ml.call_count == 2
        targets = [call.kwargs["target"] for call in ml.call_args_list]
        assert all(target is not None for target in targets)
        assert targets[0] is targets[1]
        assert targets[0].interpreter == sys.executable

    @patch("peta.core.resolve.local_get_package")
    def test_compare_json_reports_the_target(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        result = runner.invoke(
            app,
            [
                "compare",
                "requests",
                "httpx",
                "--local",
                "--python",
                sys.executable,
                "--json",
            ],
        )
        environment = json.loads(result.output)["query"]["target_environment"]
        assert environment["interpreter"] == sys.executable
        assert environment["markers"]["sys_platform"] == sys.platform

    @patch("peta.core.resolve.local_get_package")
    def test_compare_human_output_describes_the_target(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        result = runner.invoke(
            app,
            [
                "compare",
                "requests",
                "httpx",
                "--local",
                "--python",
                sys.executable,
                "--format",
                "text",
            ],
        )
        assert "Target environment:" in result.output
        assert "markers:" in result.output

    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param(["info", "requests"], id="info"),
            pytest.param(["compare", "requests", "httpx"], id="compare"),
            pytest.param(["deps", "requests"], id="deps"),
            pytest.param(["files", "requests"], id="files"),
        ],
    )
    def test_invalid_target_is_recorded_in_the_error_envelope(
        self, argv: list[str]
    ) -> None:
        """A rejected target must still name what was asked for."""
        result = runner.invoke(
            app, [*argv, "--json", "--path", "/definitely/not/a/directory"]
        )
        assert result.exit_code == 2
        query = json.loads(result.output)["query"]
        assert query["arguments"]["paths"] == ["/definitely/not/a/directory"]
        assert query["arguments"]["python"] is None

    @patch("peta.core.resolve.local_get_package")
    def test_untargeted_json_still_reports_marker_values(self, ml: MagicMock) -> None:
        """An untargeted run evaluates markers too, so it must publish them."""
        ml.return_value = _pkg()
        result = runner.invoke(app, ["info", "requests", "--json"])
        markers = json.loads(result.output)["query"]["target_environment"]["markers"]
        assert markers["sys_platform"] == sys.platform
        assert markers["python_full_version"]
        assert markers["platform_python_implementation"]


class TestNotFoundAttribution:
    """A structured not-found error names the provider that reported it."""

    def test_fallback_miss_is_attributed_to_pypi(self) -> None:
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
        # The local-first path fell through to PyPI, which reported the miss.
        assert data["errors"][0]["source"] == "pypi"

    @patch("peta.core.resolve.local_get_package")
    def test_forced_local_miss_is_attributed_to_local(self, ml: MagicMock) -> None:
        ml.side_effect = LocalNotFound("missing")
        r = runner.invoke(app, ["info", "missing", "--local", "--format", "json"])
        assert r.exit_code == 1
        assert json.loads(r.output)["errors"][0]["source"] == "local"


class TestJsonAlias:
    """``--json`` is an alias for ``--format json``, not an override."""

    @patch("peta.core.resolve.local_get_package")
    def test_alone_selects_json(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json"])
        assert r.exit_code == 0
        assert json.loads(r.output)["result"]["name"] == "requests"

    @patch("peta.core.resolve.local_get_package")
    def test_rejects_explicit_rich(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json", "--format", "rich"])
        assert r.exit_code == 2
        assert "--json cannot be combined" in r.output

    @patch("peta.core.resolve.local_get_package")
    def test_rejects_explicit_text(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        r = runner.invoke(app, ["info", "requests", "--json", "--format", "text"])
        assert r.exit_code == 2


class TestOutputContract:
    def test_json_invalid_package_is_structured(self) -> None:
        r = runner.invoke(app, ["info", "==", "--format", "json"])
        assert r.exit_code == 2
        data = json.loads(r.output)
        assert data["schema_version"] == "2"
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
        assert data["schema_version"] == "2"
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

    @patch("peta.core.providers.builtin.osv.get_vulnerabilities")
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

    @patch("peta.core.providers.builtin.stats.get_dependent_count")
    @patch("peta.core.providers.builtin.stats.get_download_count")
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
        assert result.output.startswith("# Declared metadata tree for requests")

    @patch("peta.core.resolve.remote_get_package_matching")
    def test_deps_remote_flag(self, mr: MagicMock) -> None:
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "requests", "-r"]).exit_code == 0
        assert mr.call_args_list[0].args[0] == "requests"

    @patch("peta.core.resolve.local_get_package")
    def test_deps_local_flag(self, ml: MagicMock) -> None:
        ml.return_value = _pkg()
        assert runner.invoke(app, ["deps", "requests", "-l"]).exit_code == 0
        assert ml.call_args_list[0].args == ("requests",)

    @patch("peta.core.resolve.remote_get_package_matching")
    @patch("peta.core.resolve.local_get_package")
    def test_deps_fallback_to_remote(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.return_value = _pkg(source="remote")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 0

    @patch("peta.core.resolve.remote_get_package_matching")
    @patch("peta.core.resolve.local_get_package")
    def test_deps_not_found(self, ml: MagicMock, mr: MagicMock) -> None:
        ml.side_effect = LocalNotFound("x")
        mr.side_effect = RemoteNotFound("x")
        assert runner.invoke(app, ["deps", "x"]).exit_code == 1

    @patch("peta.core.resolve.remote_get_package_matching")
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
        m.return_value = ([{"version": "2.31.0", "upload_time": "2023-05-22"}], _LIVE)
        assert "2.31.0" in runner.invoke(app, ["versions", "requests"]).output

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_json(self, m: MagicMock) -> None:
        m.return_value = ([{"version": "2.31.0", "upload_time": "2023-05-22"}], _LIVE)
        assert isinstance(
            json.loads(runner.invoke(app, ["versions", "requests", "--json"]).output)[
                "result"
            ]["versions"],
            list,
        )

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_markdown(self, m: MagicMock) -> None:
        m.return_value = ([{"version": "2.31.0", "upload_time": "2023-05-22"}], _LIVE)
        result = runner.invoke(app, ["versions", "requests", "--format", "markdown"])
        assert result.output.startswith("# Versions for requests")

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_not_found(self, m: MagicMock) -> None:
        m.return_value = ([], _LIVE)
        assert runner.invoke(app, ["versions", "nope"]).exit_code == 1

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_limit(self, m: MagicMock) -> None:
        m.return_value = (
            [{"version": f"1.{i}.0", "upload_time": ""} for i in range(4, -1, -1)],
            _LIVE,
        )
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


class TestArtifacts:
    def _release(self, **over: object) -> ReleaseArtifacts:
        wheel = ArtifactFile(
            filename="requests-2.31.0-py3-none-any.whl",
            url="https://files.invalid/requests-2.31.0-py3-none-any.whl",
            kind="wheel",
            compatibility=Compatibility(compatible=True),
            size=64000,
            sha256="c" * 64,
        )
        base = ReleaseArtifacts(
            name="requests", version="2.31.0", target=Target(), files=[wheel]
        )
        return replace(base, **over)

    @patch("peta.cli.commands.artifacts.get_release")
    def test_summary(self, m: MagicMock) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests"])
        assert result.exit_code == 0
        assert "requests 2.31.0" in result.output

    @patch("peta.cli.commands.artifacts.get_release")
    def test_json(self, m: MagicMock) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests", "--json"])
        data = json.loads(result.output)
        assert data["query"]["command"] == "artifacts"
        assert data["result"]["summary"]["wheels"] == 1

    @patch("peta.cli.commands.artifacts.get_release")
    def test_files_and_version_specifier(self, m: MagicMock) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests==2.31.0", "--files"])
        assert result.exit_code == 0
        assert "requests-2.31.0-py3-none-any.whl" in result.output
        assert m.call_args.args == ("requests", "2.31.0")

    @patch("peta.cli.commands.artifacts.get_release")
    def test_provenance_flag_is_passed_through(self, m: MagicMock) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests", "--provenance"])
        assert result.exit_code == 0
        assert m.call_args.kwargs["publishers"] is True

    @patch("peta.cli.commands.artifacts.get_release")
    def test_python_target_reaches_the_lookup(self, m: MagicMock) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests", "--python", "3.13"])
        assert result.exit_code == 0
        assert m.call_args.kwargs["target"].python == "3.13"

    @patch("peta.cli.commands.artifacts.get_release")
    @pytest.mark.parametrize(
        ("fmt", "expected"),
        [("markdown", "# Artifacts for requests 2.31.0"), ("text", "Artifacts for")],
    )
    def test_other_formats(self, m: MagicMock, fmt: str, expected: str) -> None:
        m.return_value = (self._release(), _LIVE)
        result = runner.invoke(app, ["artifacts", "requests", "--format", fmt])
        assert expected in result.output

    def test_invalid_python_target_exits_2(self) -> None:
        result = runner.invoke(app, ["artifacts", "requests", "--python", "nope"])
        assert result.exit_code == 2
        assert "Invalid Python version" in result.output

    def test_invalid_package_argument_exits_2(self) -> None:
        assert runner.invoke(app, ["artifacts", "requests=="]).exit_code == 2

    @patch("peta.cli.commands.artifacts.get_release")
    def test_unknown_package_exits_1(self, m: MagicMock) -> None:
        m.return_value = (None, _LIVE)
        result = runner.invoke(app, ["artifacts", "nope-xyz"])
        assert result.exit_code == 1
        assert "Package 'nope-xyz' not found" in result.output

    @patch("peta.cli.commands.artifacts.get_release")
    def test_a_missing_release_is_not_reported_as_a_missing_package(
        self, m: MagicMock
    ) -> None:
        # The project can exist while the pinned release does not.
        m.return_value = (None, _LIVE)
        result = runner.invoke(app, ["artifacts", "requests==99.0"])
        assert result.exit_code == 1
        assert "Release 'requests==99.0' not found" in result.output

    @patch("peta.cli.commands.artifacts.get_release")
    def test_network_error_exits_2(self, m: MagicMock) -> None:
        from peta.core.remote import NetworkError

        m.side_effect = NetworkError("down")
        assert runner.invoke(app, ["artifacts", "requests"]).exit_code == 2

    @patch("peta.cli.commands.artifacts.get_release")
    def test_offline_miss_exits_2(self, m: MagicMock) -> None:
        from peta.core.http import OfflineError

        m.side_effect = OfflineError("https://pypi.org/simple/requests/")
        result = runner.invoke(app, ["artifacts", "requests", "--json"])
        assert result.exit_code == 2
        assert json.loads(result.output)["errors"][0]["code"] == "offline_unavailable"


class TestShorthandPosition:
    """Where ``info`` is inserted for the ``peta <package>`` shorthand."""

    @pytest.mark.parametrize(
        ("args", "expected"),
        [
            (["requests"], 1),
            (["--offline", "requests"], 2),
            (["--offline", "--refresh", "requests"], 3),
            (["--no-color", "requests"], 2),
            # --cache-dir consumes the token after it, which is not a package.
            (["--cache-dir", "somewhere", "requests"], 3),
            (["requests==2.31.0"], 1),
        ],
    )
    def test_a_package_after_root_options_still_gets_info(
        self, args: list[str], expected: int
    ) -> None:
        # Root options precede the subcommand in any Click application, so
        # the shorthand has to skip them before it can tell a package name
        # from a command. The cache flags would otherwise have broken it.
        assert _shorthand_position(args) == expected

    @pytest.mark.parametrize(
        "args",
        [
            [],
            ["info", "requests"],
            ["compare", "a", "b"],
            ["--cache-dir", "somewhere", "info", "requests"],
            ["--help"],
            ["--version"],
            ["--offline"],
        ],
    )
    def test_nothing_is_inserted_when_a_command_is_already_named(
        self, args: list[str]
    ) -> None:
        assert _shorthand_position(args) is None


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


_PYPI_BODY = {
    "info": {"name": "requests", "version": "2.31.0", "summary": "http"},
    "vulnerabilities": [],
}


class TestCacheAndOffline:
    """The cache and ``--offline`` as a user meets them, through the CLI."""

    def test_a_repeated_versioned_query_needs_no_network(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        # The headline promise: a pinned release's metadata cannot change, so
        # asking twice must cost one request — and the second must succeed
        # with the network taken away entirely.
        fake_http.reply(json=_PYPI_BODY)
        warm = ["info", "requests==2.31.0", "--no-osv", "--no-stats", "--json"]
        cached = ["--offline", *warm]

        first = runner.invoke(app, ["--cache-dir", str(tmp_path), *warm])
        second = runner.invoke(app, ["--cache-dir", str(tmp_path), *cached])

        assert first.exit_code == 0
        assert second.exit_code == 0
        assert json.loads(second.output)["result"]["version"] == "2.31.0"
        assert len(fake_http.requests) == 1

    def test_the_envelope_says_where_the_data_came_from(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        fake_http.reply(json=_PYPI_BODY)
        args = ["info", "requests==2.31.0", "--no-osv", "--no-stats", "--json"]

        first = runner.invoke(app, ["--cache-dir", str(tmp_path), *args])
        second = runner.invoke(app, ["--cache-dir", str(tmp_path), *args])

        live = json.loads(first.output)["sources"][0]
        served = json.loads(second.output)["sources"][0]
        assert live["freshness"] == "live"
        assert served["freshness"] == "cached"

    def test_offline_with_an_empty_cache_fails_with_a_structured_error(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "--offline",
                "--cache-dir",
                str(tmp_path),
                "info",
                "requests==2.31.0",
                "--json",
            ],
        )

        assert result.exit_code == 2
        envelope = json.loads(result.output)
        assert envelope["status"] == "failed"
        assert envelope["errors"][0]["code"] == "offline_unavailable"
        # Actionable means naming exactly what could not be answered. Asserted
        # whole rather than by substring: a hostname substring check is the
        # shape of a bypassable URL guard, and the exact message is what the
        # contract promises anyway.
        assert envelope["errors"][0]["message"] == (
            "offline and no cached response for "
            "https://pypi.org/pypi/requests/2.31.0/json"
        )
        assert fake_http.requests == []

    def test_refresh_refetches_a_cached_answer(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        fake_http.reply(json=_PYPI_BODY)
        args = ["info", "requests==2.31.0", "--no-osv", "--no-stats", "--json"]

        _ = runner.invoke(app, ["--cache-dir", str(tmp_path), *args])
        _ = runner.invoke(app, ["--cache-dir", str(tmp_path), "--refresh", *args])

        assert len(fake_http.requests) == 2

    def test_offline_and_refresh_are_rejected_together(self, tmp_path: Path) -> None:
        # Contradictory: one says refetch everything, the other says make no
        # requests. Either reading could be meant, so neither is guessed.
        # Asserted through the JSON envelope rather than the rendered text,
        # which Rich decorates with escape codes that split the option names.
        result = runner.invoke(
            app,
            [
                "--offline",
                "--refresh",
                "--cache-dir",
                str(tmp_path),
                "info",
                "requests",
                "--json",
            ],
        )

        assert result.exit_code == 2
        envelope = json.loads(result.output)
        assert envelope["status"] == "failed"
        assert envelope["errors"][0]["code"] == "invalid_arguments"
        assert "cannot be combined" in envelope["errors"][0]["message"]

    def test_optional_enrichment_survives_being_offline(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        # Offline must not turn a usable result into a failure just because an
        # optional source could not be reached.
        fake_http.reply(json=_PYPI_BODY)
        # ``--no-osv``/``--no-stats`` are command options, so they follow the
        # subcommand; only the cache flags belong before it.
        warm = ["info", "requests==2.31.0", "--json", "--no-osv", "--no-stats"]
        _ = runner.invoke(app, ["--cache-dir", str(tmp_path), *warm])

        result = runner.invoke(
            app,
            [
                "--cache-dir",
                str(tmp_path),
                "--offline",
                "info",
                "requests==2.31.0",
                "--json",
            ],
        )

        assert result.exit_code == 0
        envelope = json.loads(result.output)
        assert envelope["status"] == "partial"
        assert envelope["result"]["version"] == "2.31.0"
        reasons = [source.get("reason", "") for source in envelope["sources"]]
        assert any("offline" in reason for reason in reasons)


class TestShorthandWithCacheFlags:
    def test_a_root_flag_before_the_package_works_end_to_end(
        self, fake_http: FakeTransport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The whole point of the rewrite: `peta --offline requests` must run
        # the info command, not fail with "no such command 'requests'".
        fake_http.reply(json=_PYPI_BODY)
        argv = ["peta", "--cache-dir", str(tmp_path), "requests==2.31.0", "--json"]
        monkeypatch.setattr("sys.argv", argv)
        captured: list[list[str]] = []
        monkeypatch.setattr("peta.cli.app.app", lambda: captured.append(list(sys.argv)))

        run()

        assert captured[0][1:4] == ["--cache-dir", str(tmp_path), "info"]


class TestCompareConcurrency:
    def test_both_packages_are_fetched_at_the_same_time(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        # The two sides are unrelated lookups; waiting for the first before
        # starting the second doubled the command's latency.
        started = threading.Barrier(2, timeout=5)

        def wait_for_the_other(_request: httpx.Request) -> None:
            _ = started.wait()

        fake_http.on_request = wait_for_the_other
        fake_http.reply(
            url="/requests/", json={"info": {"name": "requests", "version": "1.0"}}
        )
        fake_http.reply(
            url="/httpx/", json={"info": {"name": "httpx", "version": "1.0"}}
        )

        result = runner.invoke(
            app,
            [
                "--cache-dir",
                str(tmp_path),
                "compare",
                "requests",
                "httpx",
                "--remote",
                "--no-osv",
                "--no-stats",
                "--json",
            ],
        )

        # The barrier can only clear if both lookups are in flight at once.
        assert result.exit_code == 0

    def test_the_left_package_stays_on_the_left(
        self, fake_http: FakeTransport, tmp_path: Path
    ) -> None:
        # Which side a package is rendered on must not depend on which
        # answered first, so the slower one is asked for first.
        def delay_the_left_one(request: httpx.Request) -> None:
            if "/requests/" in str(request.url):
                time.sleep(0.05)

        fake_http.on_request = delay_the_left_one
        fake_http.reply(
            url="/requests/", json={"info": {"name": "requests", "version": "1.0"}}
        )
        fake_http.reply(
            url="/httpx/", json={"info": {"name": "httpx", "version": "1.0"}}
        )

        result = runner.invoke(
            app,
            [
                "--cache-dir",
                str(tmp_path),
                "compare",
                "requests",
                "httpx",
                "--remote",
                "--no-osv",
                "--no-stats",
                "--json",
            ],
        )

        packages = json.loads(result.output)["result"]["packages"]
        assert [p["name"] for p in packages] == ["requests", "httpx"]
