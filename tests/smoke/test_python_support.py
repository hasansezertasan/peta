"""Smoke: the declared Python support is what gets built and tested.

tox installs the built wheel into every test env, so the installed ``peta``
distribution's metadata here *is* the wheel's ``METADATA``. Checking it against
the tox and CI configuration means ``requires-python`` cannot be lowered
without a classifier, a tox env and a CI row for the new floor.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import metadata
from pathlib import Path
from typing import Any

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


def _pyproject() -> dict[str, Any]:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _ci_job() -> str:
    """Return the ``ci`` job's block of the workflow, up to the next job."""
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")
    job = re.search(r"^  ci:\n(?P<body>(?:(?:    .*)?\n)*)", workflow, re.MULTILINE)
    assert job is not None, "ci.yml has no ci job"
    return job["body"]


def test_tox_has_a_test_env_per_classified_version() -> None:
    env_list: list[str] = _pyproject()["tool"]["tox"]["env_list"]
    envs = [env for env in env_list if _VERSION_ENV.match(env)]
    assert envs == _minors(_classified_versions())


def test_linters_and_type_checkers_target_the_floor() -> None:
    """Checking against the oldest interpreter catches newer stdlib APIs."""
    tool = _pyproject()["tool"]
    floor = _minors(_classified_versions())[0]
    assert tool["ruff"]["target-version"] == "py" + floor.replace(".", "")
    assert tool["mypy"]["python_version"] == floor
    assert tool["basedpyright"]["pythonVersion"] == floor
    assert tool["ty"]["environment"]["python-version"] == floor
    assert tool["pyrefly"]["python-version"] == floor


def test_style_env_runs_on_and_checks_the_ceiling() -> None:
    style = _pyproject()["tool"]["tox"]["env"]["style"]
    ceiling = _minors(_classified_versions())[-1]
    assert style["base_python"] == [ceiling]
    assert ["mypy", "--python-version", ceiling] in style["commands"]


_IN_REPO = pytest.mark.skipif(
    not _CI_WORKFLOW.exists(), reason="the sdist ships neither .github/ nor dotfiles"
)


@_IN_REPO
def test_ci_matrix_has_a_row_per_classified_version() -> None:
    job = _ci_job()
    row = re.search(r"^\s*python-version: \[(?P<versions>[^\]]*)\]", job, re.MULTILINE)
    assert row is not None, "the ci job has no python-version matrix"
    matrix = [entry.strip().strip("\"'") for entry in row["versions"].split(",")]
    assert matrix == _minors(_classified_versions())
    # A row dropped (or added) per OS would escape the list comparison above.
    assert not re.search(r"^\s*(?:exclude|include):", job, re.MULTILINE)


@_IN_REPO
def test_dev_interpreter_is_the_ceiling_and_gates_the_style_step() -> None:
    """The non-test envs run on one matrix row, which must exist."""
    ceiling = _minors(_classified_versions())[-1]
    dev = (_ROOT / ".python-version").read_text(encoding="utf-8").strip()
    assert dev == ceiling
    step = re.search(
        r"^      - name: Run style, docs and CLI checks\n(?P<body>(?:        .*\n)*)",
        _ci_job(),
        re.MULTILINE,
    )
    assert step is not None, "the ci job has no style/docs/CLI step"
    assert f"if: ${{{{ matrix.python-version == '{ceiling}' }}}}" in step["body"]
