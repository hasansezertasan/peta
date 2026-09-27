"""Smoke: the declared Python support is what gets built and tested.

tox installs the built wheel into every test env, so the installed ``peta``
distribution's metadata here *is* the wheel's ``METADATA``. Checking it against
the tox and CI configuration means ``requires-python`` cannot be lowered
without a classifier, a tox env and a CI row for the new floor.
"""

from __future__ import annotations

import re
import sys
import tomllib
from importlib.metadata import metadata
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

pytestmark = pytest.mark.smoke

_ROOT = Path(__file__).resolve().parents[2]
_CI_WORKFLOW = _ROOT / ".github" / "workflows" / "ci.yml"
_VERSION_CLASSIFIER = re.compile(r"^Programming Language :: Python :: (3\.\d+)$")
_VERSION_ENV = re.compile(r"^3\.\d+$")


def _requires_python() -> SpecifierSet:
    return SpecifierSet(metadata("peta")["Requires-Python"])


def _classified_versions() -> list[Version]:
    classifiers = metadata("peta").get_all("Classifier") or []
    found = (_VERSION_CLASSIFIER.match(entry) for entry in classifiers)
    return sorted(Version(match[1]) for match in found if match)


def _minors(versions: list[Version]) -> list[str]:
    return [f"{version.major}.{version.minor}" for version in versions]


def test_requires_python_is_a_single_floor() -> None:
    """A plain ``>=3.X``: the classifiers below then pin down every minor."""
    (specifier,) = _requires_python()
    assert specifier.operator == ">="
    assert len(Version(specifier.version).release) == 2  # 3.X, not 3.X.Y


def test_classifiers_run_contiguously_from_the_floor() -> None:
    requires = _requires_python()
    versions = _classified_versions()
    assert versions, "no Programming Language :: Python :: 3.X classifiers"
    floor = versions[0]
    below = Version(f"{floor.major}.{floor.minor - 1}")
    assert floor in requires
    assert below not in requires
    expected = [
        Version(f"{floor.major}.{minor}")
        for minor in range(floor.minor, versions[-1].minor + 1)
    ]
    assert versions == expected


def test_running_interpreter_is_declared() -> None:
    """Every interpreter the suite runs on must be a classified one."""
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert running in _minors(_classified_versions())


def test_tox_has_a_test_env_per_classified_version() -> None:
    pyproject = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    env_list: list[str] = pyproject["tool"]["tox"]["env_list"]
    envs = [env for env in env_list if _VERSION_ENV.match(env)]
    assert envs == _minors(_classified_versions())


@pytest.mark.skipif(
    not _CI_WORKFLOW.exists(), reason="the sdist does not ship .github/"
)
def test_ci_matrix_has_a_row_per_classified_version() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")
    row = re.search(
        r"^\s*python-version: \[(?P<versions>[^\]]*)\]", workflow, re.MULTILINE
    )
    assert row is not None, "ci.yml has no python-version matrix"
    matrix = [entry.strip().strip("\"'") for entry in row["versions"].split(",")]
    assert matrix == _minors(_classified_versions())
