"""Unit tests for the local metadata fetcher (importlib.metadata mocked)."""

import json
import subprocess  # ruff: ignore[suspicious-subprocess-import] # Only for TimeoutExpired/CompletedProcess.
import sys
from email.message import Message
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from packaging.markers import default_environment

from peta.core.local import (
    InvalidTargetError,
    LocalTarget,
    PackageNotFoundError,
    get_package,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


def test_interpreter_target_marker_environment_matches_packaging() -> None:
    target = LocalTarget.create(sys.executable)
    expected = default_environment()
    assert (
        target.marker_environment["implementation_name"]
        == expected["implementation_name"]
    )
    assert (
        target.marker_environment["implementation_version"]
        == expected["implementation_version"]
    )


def test_interpreter_inspection_uses_a_timeout() -> None:
    """A hung interpreter must fail the command, not block it forever."""
    with patch("peta.core.local.subprocess.run") as run:
        run.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=15.0)
        with pytest.raises(InvalidTargetError, match="did not respond"):
            LocalTarget.create(sys.executable)
        assert run.call_args.kwargs["timeout"] > 0


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("[]", id="list-payload"),
        pytest.param("42", id="scalar-payload"),
        pytest.param('{"paths": [], "marker_environment": []}', id="marker-not-a-map"),
        pytest.param('{"paths": {}, "marker_environment": {}}', id="paths-not-a-list"),
        pytest.param(
            '{"paths": [1], "marker_environment": {"sys_platform": "linux"}}',
            id="non-string-path",
        ),
        pytest.param(
            '{"paths": [], "marker_environment": {"sys_platform": 1}}',
            id="non-string-marker-value",
        ),
        pytest.param(
            '{"paths": [], "marker_environment": {"sys_platform": "linux"}}',
            id="missing-required-markers",
        ),
    ],
)
def test_malformed_inspection_payload_rejected(payload: str) -> None:
    """Every layer of the payload is checked before any of it is used."""
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload)
    with (
        patch("peta.core.local.subprocess.run", return_value=completed),
        pytest.raises(InvalidTargetError, match="invalid environment data"),
    ):
        LocalTarget.create(sys.executable)


def test_valid_payload_is_accepted() -> None:
    markers = {
        "platform_python_implementation": "CPython",
        "python_full_version": "3.14.0",
        "sys_platform": "linux",
    }
    stdout = json.dumps({"paths": ["/site-packages"], "marker_environment": markers})
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)
    with patch("peta.core.local.subprocess.run", return_value=completed):
        target = LocalTarget.create(sys.executable)
    assert target.paths == ("/site-packages",)
    assert target.marker_environment == markers
    assert target.output_environment()["markers"] == markers


def test_describe_reports_the_marker_values() -> None:
    target = LocalTarget(
        paths=("/site-packages",),
        interpreter=None,
        marker_environment={
            "platform_python_implementation": "PyPy",
            "python_full_version": "3.11.9",
            "sys_platform": "darwin",
        },
    )
    described = target.describe()
    assert "PyPy" in described
    assert "3.11.9" in described
    assert "darwin" in described


def test_invalid_metadata_path_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(InvalidTargetError, match="expected an existing directory"):
        LocalTarget.create(None, (str(missing),))


def _msg(**headers: str) -> Message:
    msg = Message()
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    return msg


@patch("peta.core.local.importlib_metadata")
def test_minimal_missing_optionals(mock_meta: MagicMock) -> None:
    dist = MagicMock()
    dist.metadata = _msg(Name="minimal-pkg", Version="1.0.0")
    dist.requires = None
    dist.files = None
    mock_meta.distribution.return_value = dist

    result = get_package("minimal-pkg")
    assert result.name == "minimal-pkg"
    assert result.version == "1.0.0"
    assert result.source == "local"
    assert result.author is None
    assert result.dependencies == []
    assert result.files is None
    assert result.retrieved_at is not None


@patch("peta.core.local.importlib_metadata")
def test_parses_urls_keywords_deps_files(mock_meta: MagicMock) -> None:
    md = _msg(
        Name="rich",
        Version="13.0.0",
        Summary="pretty",
        Keywords="cli, tui",
        License="BSD-3-Clause",
    )
    md["Project-URL"] = "Source, https://github.com/Textualize/rich"
    md["Classifier"] = "Programming Language :: Python :: 3"
    dist = MagicMock()
    dist.metadata = md
    dist.requires = ["pygments>=2.6"]
    dist.files = ["rich/__init__.py", "rich/console.py"]
    mock_meta.distribution.return_value = dist

    result = get_package("rich")
    assert result.project_urls == {"Source": "https://github.com/Textualize/rich"}
    assert result.keywords == ["cli", "tui"]
    assert result.dependencies == ["pygments>=2.6"]
    assert result.files == ["rich/__init__.py", "rich/console.py"]
    assert result.classifiers == ["Programming Language :: Python :: 3"]
    assert result.license == "BSD-3-Clause"
    assert result.license_source == "legacy"


@patch("peta.core.local.importlib_metadata")
def test_prefers_license_expression(mock_meta: MagicMock) -> None:
    dist = MagicMock()
    dist.metadata = _msg(
        Name="modern-license",
        Version="1.0.0",
        Metadata_Version="2.4",
        License_Expression="MIT",
    )
    dist.requires = None
    dist.files = None
    mock_meta.distribution.return_value = dist

    result = get_package("modern-license")
    assert result.license == "MIT"
    assert result.license_source == "expression"


@patch("peta.core.local.importlib_metadata")
def test_skips_malformed_project_url(mock_meta: MagicMock) -> None:
    md = _msg(Name="x", Version="1.0.0")
    md["Project-URL"] = "MalformedNoComma"
    dist = MagicMock()
    dist.metadata = md
    dist.requires = None
    dist.files = None
    mock_meta.distribution.return_value = dist

    result = get_package("x")
    assert result.project_urls == {}


@patch("peta.core.local.importlib_metadata")
def test_not_found_raises(mock_meta: MagicMock) -> None:
    import importlib.metadata as real

    mock_meta.PackageNotFoundError = real.PackageNotFoundError
    mock_meta.distribution.side_effect = real.PackageNotFoundError("x")
    with pytest.raises(PackageNotFoundError):
        get_package("nope-xyz")


@patch("peta.core.local.importlib_metadata")
def test_nameless_distribution_does_not_hide_later_packages(
    mock_meta: MagicMock,
) -> None:
    """A corrupt .dist-info enumerated first must be skipped, not crash the scan."""
    import importlib.metadata as real

    mock_meta.PackageNotFoundError = real.PackageNotFoundError
    corrupt = MagicMock()
    corrupt.metadata = _msg(Version="0.0.0")
    wanted = MagicMock()
    wanted.metadata = _msg(Name="wanted-pkg", Version="2.0.0")
    wanted.requires = None
    wanted.files = None
    mock_meta.distributions.return_value = iter([corrupt, wanted])

    target = LocalTarget(
        paths=("/site-packages",), interpreter=None, marker_environment={}
    )
    result = get_package("wanted-pkg", target=target)
    assert result.name == "wanted-pkg"
    assert result.version == "2.0.0"


@patch("peta.core.local.importlib_metadata")
def test_nameless_distribution_alone_reports_not_found(mock_meta: MagicMock) -> None:
    import importlib.metadata as real

    mock_meta.PackageNotFoundError = real.PackageNotFoundError
    corrupt = MagicMock()
    corrupt.metadata = _msg(Version="0.0.0")
    mock_meta.distributions.return_value = iter([corrupt])

    target = LocalTarget(
        paths=("/site-packages",), interpreter=None, marker_environment={}
    )
    with pytest.raises(PackageNotFoundError):
        get_package("wanted-pkg", target=target)


def test_local_target_platform_override_updates_platform_family() -> None:
    target = LocalTarget.create(platform="win32")
    assert target.marker_environment["sys_platform"] == "win32"
    assert target.marker_environment["os_name"] == "nt"
    assert target.marker_environment["platform_system"] == "Windows"

    target_linux = LocalTarget.create(platform="linux")
    assert target_linux.marker_environment["sys_platform"] == "linux"
    assert target_linux.marker_environment["os_name"] == "posix"
    assert target_linux.marker_environment["platform_system"] == "Linux"


@pytest.mark.parametrize(
    ("requested", "short", "full"),
    [("3.12", "3.12", "3.12.0"), ("3.12.4", "3.12", "3.12.4")],
)
def test_local_target_python_version_override(
    requested: str, short: str, full: str
) -> None:
    target = LocalTarget.create(python_version=requested)

    assert target.marker_environment["python_version"] == short
    assert target.marker_environment["python_full_version"] == full


@pytest.mark.parametrize("requested", ["3", "3.12.4.5", "3.x"])
def test_local_target_rejects_invalid_python_version(requested: str) -> None:
    with pytest.raises(InvalidTargetError, match=r"expected X\.Y or X\.Y\.Z"):
        LocalTarget.create(python_version=requested)


def test_local_target_rejects_blank_platform() -> None:
    with pytest.raises(InvalidTargetError, match="expected a marker platform"):
        LocalTarget.create(platform="")


def test_local_target_accepts_custom_sys_platform() -> None:
    target = LocalTarget.create(platform="custom-os")

    assert target.marker_environment["sys_platform"] == "custom-os"
