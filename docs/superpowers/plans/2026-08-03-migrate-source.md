# Source Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `copier-pyproject` skeleton in `src/peta/**` with the real 3-layer "package metadata viewer" implementation, conformed to the scaffold's strict tooling, documented reality-first.

**Architecture:** Three layers — `cli` (Typer wiring + thin command handlers) → `core` (dataclass models, `importlib.metadata` local reader, PyPI JSON client) → `output` (Rich renderers, JSON formatters). A `run()` wrapper makes `peta <pkg>` shorthand for `peta info <pkg>`. Version is dynamic (hatch-vcs from git tags); no version literal is committed.

**Tech Stack:** Python 3.14+, Typer, Rich, httpx, packaging; hatchling + hatch-vcs; pytest + pytest-cov; ruff, mypy, basedpyright; Sphinx docs; uv; tox.

## Global Constraints

- `requires-python = ">=3.14"` — single target across ruff `target-version`, mypy `python_version`, basedpyright `pythonVersion`, tox envs, and trove classifiers. Copy `py314` / `3.14` verbatim.
- Runtime deps exactly: `["typer", "rich", "httpx", "packaging"]` in `[project].dependencies`. No `cli`/`tui`/`all` extras; no `peta-tui` script.
- Entry point: `peta = "peta.cli.app:run"`.
- Never edit `src/peta/_version.py` (hatch-vcs generated). No version literal anywhere in source/docs/commits.
- Strict gates must pass: ruff `select = ALL`, mypy strict, basedpyright, cyclomatic complexity ≤ 5, coverage `fail_under = 99` on the offline tiers (smoke + unit + integration).
- **Never** name the internal reference repository or its URL in source, docs, comments, or commit messages. Refer to it only as "the reference implementation."
- No AI-authorship trailers/footers in commits or docs. Conventional Commits.
- **Reference source of truth (this session only):** the reference was cloned
  read-only into a local temporary directory. This plan embeds the conformed
  target code; the clone is only a cross-check.
- **Ruff gating rule (skill gotcha #1):** the template sets ruff `fix=true`+`unsafe-fixes`. Before running any hook or `ruff check` that autofixes, run `uv run ruff check --diff src tests` and review. Autofix can silently delete `typer.echo`/`print` patterns — inspect before applying.

---

### Task 1: Project configuration (pyproject, deps, Python 3.14, markers)

**Files:**
- Modify: `pyproject.toml` (`requires-python`, `dependencies`, `optional-dependencies`, `[project.scripts]`, classifiers, ruff/mypy/basedpyright targets, tox env list, `[tool.pytest.ini_options]` markers, `per-file-ignores`)

**Interfaces:**
- Produces: installable env with `typer,rich,httpx,packaging`; `peta` console script → `peta.cli.app:run`; pytest markers `smoke,unit,integration,e2e`.

- [ ] **Step 1: Set the dependency block and drop extras/tui script**

In `pyproject.toml` `[project]`:
```toml
requires-python = ">=3.14"
dependencies = [
  "typer",
  "rich",
  "httpx",
  "packaging",
]
```
Delete the entire `[project.optional-dependencies]` block (`cli`/`tui`/`all`).

In `[project.scripts]` — remove the `peta-tui` line and set:
```toml
[project.scripts]
peta = "peta.cli.app:run"
```

- [ ] **Step 2: Fix trove classifiers to a single Python 3.14 target**

In `[project].classifiers`, remove every `Programming Language :: Python :: 3.x` line for 3.9–3.13 and any PyPy line; keep/add:
```toml
"Programming Language :: Python :: 3",
"Programming Language :: Python :: 3.14",
"Programming Language :: Python :: Implementation :: CPython",
```
Keep the existing `Development Status`, `Environment :: Console`, `Intended Audience :: Developers`, `Topic :: *`, `Typing :: Typed` lines.

- [ ] **Step 3: Retarget the linters/type-checkers to 3.14**

- `[tool.ruff]` → `target-version = "py314"`
- `[tool.mypy]` → `python_version = "3.14"`
- basedpyright config → `pythonVersion = "3.14"` (search for the existing `3.10` under `[tool.basedpyright]` / `[tool.pyright]`)
- tox: in the `env_list` / `envlist`, collapse the Python matrix to a single `py314` (and keep `style`, `docs`, etc.). Update any `[testenv]` `basepython`/matrix references from `3.10`–`3.13` to `3.14`.

Search-and-verify: `uv run grep -rnE '3\.(9|10|11|12|13)|py3(9|10|11|12|13)' pyproject.toml` must return nothing after this step (except unrelated hits — inspect each).

- [ ] **Step 4: Register pytest markers**

In `[tool.pytest.ini_options]` add:
```toml
markers = [
  "smoke: fast import/entrypoint checks",
  "unit: pure logic, fully mocked, no I/O",
  "integration: real components wired, no external network",
  "e2e: full CLI via entry point; e2e-remote hits real PyPI (opt-in)",
]
```

- [ ] **Step 5: Add deliberate per-file-ignores**

In `[tool.ruff.lint.per-file-ignores]` add (these are the standard, necessary Typer/dataclass patterns):
```toml
"src/peta/cli/**/*.py" = ["B008", "FBT001", "FBT002"]  # Typer uses Option()/Argument() defaults and bool flags
"src/peta/core/models.py" = ["A003"]                    # dataclass fields `id`/`license` shadow builtins by design
"tests/**/*.py" = ["S101", "PLR2004", "INP001"]         # pytest asserts, magic values, implicit namespace test pkgs
```
Keep any per-file-ignores already present that still apply; remove ones that reference deleted skeleton paths (`main.py`, `tui`, `utils`).

- [ ] **Step 6: Sync and verify config resolves**

Run: `uv sync`
Expected: resolves and installs `typer, rich, httpx, packaging`; generates `src/peta/_version.py`.
Run: `uv run python -c "import peta._version as v; print(v.__version__)"`
Expected: prints a version string (not an error).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "build: set runtime deps, py3.14 floor, and test markers"
```

---

### Task 2: Remove the skeleton and lay down empty package layout

**Files:**
- Delete: `src/peta/core/app.py`, `src/peta/core/config.py`, `src/peta/core/dirs.py`, `src/peta/core/logging_setup.py`, `src/peta/utils/` (dir), `src/peta/tui/` (dir), `src/peta/__metadata__.py`
- Delete: `tests/core/test_config.py`, `tests/core/test_logging_setup.py`, `tests/test_main.py`, `tests/cli/test_app.py`, `tests/tui/` (dir), `tests/core/__init__.py`, `tests/cli/__init__.py`, `tests/tui/__init__.py`
- Create: `src/peta/cli/commands/__init__.py`, `src/peta/output/__init__.py` (empty-ish package markers)

**Interfaces:**
- Produces: a clean `src/peta/{cli,core,output}` package skeleton with no leftover imports of removed modules.

- [ ] **Step 1: Delete skeleton source**

```bash
git rm -r src/peta/tui src/peta/utils
git rm src/peta/core/app.py src/peta/core/config.py src/peta/core/dirs.py src/peta/core/logging_setup.py src/peta/__metadata__.py
```

- [ ] **Step 2: Delete skeleton tests**

```bash
git rm -r tests/tui
git rm tests/core/test_config.py tests/core/test_logging_setup.py tests/test_main.py tests/cli/test_app.py tests/core/__init__.py tests/cli/__init__.py
```
(Keep `tests/test_smoke.py` for now — it moves in Task 10.)

- [ ] **Step 3: Create the new package dirs**

```bash
mkdir -p src/peta/cli/commands src/peta/output
printf '"""CLI command handlers."""\n' > src/peta/cli/commands/__init__.py
printf '"""Output formatters."""\n' > src/peta/output/__init__.py
```
Set `src/peta/core/__init__.py` and `src/peta/cli/__init__.py` to a single-line module docstring each (overwrite skeleton contents):
- `src/peta/core/__init__.py` → `"""Core data models and metadata fetchers."""`
- `src/peta/cli/__init__.py` → `"""Command-line interface."""`

- [ ] **Step 4: Verify no dangling imports remain**

Run: `uv run grep -rnE '__metadata__|logging_setup|core\.(app|config|dirs)|peta\.utils|peta\.tui' src tests`
Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove copier skeleton modules and their tests"
```

---

### Task 3: Documentation first (DDD contract)

**Files:**
- Modify: `README.md`, `docs/installation.rst`, `docs/usage.rst`, `docs/modules.rst`, `docs/index.rst`, `docs/conf.py`
- Create: `docs/architecture.rst`

**Interfaces:**
- Produces: the user-facing contract the code is built to match. Documents ONLY the 4 real commands, 3.14+, uvx/pipx/brew install.

- [ ] **Step 1: Rewrite `README.md`**

Remove the `<!-- TODO @hasansezertasan: ... -->` line. Keep the badge block. Below it write:
```markdown
# peta

**Human-friendly Python package metadata viewer.** Think `cargo info` for Python.

`peta` shows detailed metadata for a Python package — from your local environment
or from PyPI — with clean, Rich-formatted terminal output.

## Features

- **Local + remote** — inspect installed packages or any package on PyPI
- **Rich output** — readable tables, panels, and trees
- **Dependency listing** — see a package's declared dependencies
- **File listing** — list files installed by a local package
- **Version listing** — browse published versions from PyPI
- **JSON output** — `--json` on every command for scripting

## Installation

`peta` is an end-user CLI tool; install it into an isolated environment:

```bash
# Run without installing
uvx peta requests

# Install as a tool
uv tool install peta
pipx install peta
```

**Requires:** Python 3.14+

## Usage

```bash
peta requests                 # info (local first, falls back to PyPI)
peta info requests            # explicit info
peta info requests==2.31.0    # a specific version from PyPI
peta deps flask               # declared dependencies
peta files rich               # files installed locally
peta versions httpx           # published versions on PyPI
peta requests --json          # machine-readable output
```

### Flags

| Flag | Applies to | Meaning |
|------|-----------|---------|
| `--json` | all | JSON output |
| `--local` / `-l` | info, deps | force local lookup |
| `--remote` / `-r` | info, deps | force PyPI lookup |
| `--limit` / `-n` | versions | max versions to show (default 20) |
| `--version` / `-V` | (root) | print version and exit |

## License

MIT
```

- [ ] **Step 2: Rewrite `docs/installation.rst`**

```rst
Installation
============

``peta`` is an end-user command-line tool. Install it into an isolated
environment with your preferred tool manager.

Requirements
------------

* Python 3.14 or newer.

Using uv
--------

.. code-block:: bash

   uvx peta requests        # run without installing
   uv tool install peta     # install as a persistent tool

Using pipx
----------

.. code-block:: bash

   pipx install peta

Using pip
---------

.. code-block:: bash

   pip install peta
```

- [ ] **Step 3: Rewrite `docs/usage.rst`**

```rst
Usage
=====

``peta`` reads package metadata from your local environment or from the
PyPI JSON API and prints it with Rich formatting. Add ``--json`` to any
command for machine-readable output.

Commands
--------

.. list-table::
   :header-rows: 1

   * - Command
     - Description
   * - ``peta <package>``
     - Shorthand for ``peta info <package>``.
   * - ``peta info <package>``
     - Detailed metadata (local first, PyPI fallback).
   * - ``peta deps <package>``
     - Declared dependencies of a package.
   * - ``peta files <package>``
     - Files installed by a local package.
   * - ``peta versions <package>``
     - Published versions from PyPI.

Resolution
----------

For ``info`` and ``deps``, ``peta`` checks the local environment first and
falls back to PyPI. Force a source with ``--local``/``-l`` or
``--remote``/``-r``. A ``name==version`` argument always queries PyPI.
``files`` is local-only; ``versions`` is PyPI-only.

Exit codes
----------

.. list-table::
   :header-rows: 1

   * - Code
     - Meaning
   * - ``0``
     - Success.
   * - ``1``
     - Package not found.
   * - ``2``
     - Network or PyPI HTTP error.
```

- [ ] **Step 4: Create `docs/architecture.rst` and add it to the toctree**

Create `docs/architecture.rst`:
```rst
Architecture
============

``peta`` is organised into three layers.

CLI (``peta.cli``)
------------------

``peta.cli.app`` defines the Typer application and four commands
(``info``, ``deps``, ``files``, ``versions``). ``run()`` rewrites
``sys.argv`` so a bare ``peta <package>`` becomes ``peta info <package>``.
Each command in ``peta.cli.commands`` orchestrates a fetch and a render.

Core (``peta.core``)
--------------------

* ``peta.core.models`` — ``PackageInfo`` and ``Vulnerability`` dataclasses.
* ``peta.core.local`` — reads installed metadata via ``importlib.metadata``.
* ``peta.core.remote`` — fetches from the PyPI JSON API with ``httpx``.

Output (``peta.output``)
------------------------

* ``peta.output.tables`` — Rich renderers returning strings.
* ``peta.output.json`` — JSON string formatters.

Error model
-----------

``PackageNotFoundError`` (exit 1) and ``NetworkError`` (exit 2) are raised
by the core layer and mapped to exit codes by the command handlers.
```

In `docs/index.rst`, add `architecture` to the toctree (after `usage`):
```rst
   installation
   usage
   architecture
   modules
```

- [ ] **Step 5: Rewrite `docs/modules.rst` autodoc targets**

Replace the body's `automodule` section (keep the long-underline header comment) so it points at the real modules only:
```rst
Core (``peta.core``)
----------------------------

.. automodule:: peta.core.models

.. automodule:: peta.core.local

.. automodule:: peta.core.remote

Output (``peta.output``)
----------------------------

.. automodule:: peta.output.tables

.. automodule:: peta.output.json

CLI (``peta.cli``)
----------------------------

.. automodule:: peta.cli.app

.. automodule:: peta.cli.commands.info

.. automodule:: peta.cli.commands.deps

.. automodule:: peta.cli.commands.files

.. automodule:: peta.cli.commands.versions
```
Delete the `.. TODO @hasansezertasan:` line.

- [ ] **Step 6: Exclude the internal spec/plan from Sphinx publish (skill gotcha #9)**

In `docs/conf.py`, ensure `exclude_patterns` includes `superpowers/**`:
```python
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "superpowers/**"]
```
(Merge with whatever is already there — do not drop existing entries.)

- [ ] **Step 7: Commit the contract**

```bash
git add README.md docs/
git commit -m "docs: document the real peta CLI surface (reality-only)"
```

---

### Task 4: `core/models.py`

**Files:**
- Create: `src/peta/core/models.py`
- Test: `tests/unit/test_models.py`

**Interfaces:**
- Produces: `PackageInfo` and `Vulnerability` dataclasses (see fields below). No `DependencyNode`, no `download_count`, no `dependent_count`.

- [ ] **Step 1: Create the test dir and write the failing test**

```bash
mkdir -p tests/unit
printf '"""Unit tests (pure logic, fully mocked)."""\n' > tests/unit/__init__.py
```
`tests/unit/test_models.py`:
```python
"""Unit tests for core data models."""

import pytest

from peta.core.models import PackageInfo, Vulnerability

pytestmark = pytest.mark.unit


class TestVulnerability:
    def test_full(self) -> None:
        vuln = Vulnerability(
            id="PYSEC-2024-001",
            aliases=["CVE-2024-12345"],
            summary="SSRF vulnerability",
            fixed_in=["2.32.0"],
            severity="HIGH",
        )
        assert vuln.id == "PYSEC-2024-001"
        assert vuln.aliases == ["CVE-2024-12345"]
        assert vuln.fixed_in == ["2.32.0"]
        assert vuln.severity == "HIGH"

    def test_defaults(self) -> None:
        vuln = Vulnerability(id="GHSA-x", aliases=[], summary="s", fixed_in=[])
        assert vuln.severity is None


class TestPackageInfo:
    def test_minimal(self) -> None:
        pkg = PackageInfo(name="requests", version="2.31.0", source="local")
        assert pkg.name == "requests"
        assert pkg.source == "local"
        assert pkg.summary is None
        assert pkg.dependencies == []
        assert pkg.vulnerabilities == []

    def test_defaults(self) -> None:
        pkg = PackageInfo(name="t", version="1.0", source="remote")
        assert pkg.author is None
        assert pkg.project_urls == {}
        assert pkg.classifiers == []
        assert pkg.keywords == []
        assert pkg.files is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_models.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'peta.core.models'`.

- [ ] **Step 3: Write `src/peta/core/models.py`**

```python
"""Core data models for peta."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    """A known security vulnerability for a package."""

    id: str
    aliases: list[str]
    summary: str
    fixed_in: list[str]
    severity: str | None = None


@dataclass
class PackageInfo:
    """Package metadata from a local installation or PyPI."""

    name: str
    version: str
    source: str  # "local" or "remote"

    summary: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    license: str | None = None
    python_requires: str | None = None
    homepage: str | None = None
    project_urls: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    classifiers: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    files: list[str] | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_models.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/peta/core/models.py tests/unit/__init__.py tests/unit/test_models.py
git commit -m "feat: add PackageInfo and Vulnerability models"
```

---

### Task 5: `core/remote.py`

**Files:**
- Create: `src/peta/core/remote.py`
- Test: `tests/unit/test_remote.py`

**Interfaces:**
- Consumes: `peta.core.models.PackageInfo`, `Vulnerability`.
- Produces: `get_package(name: str, version: str | None = None) -> PackageInfo`; `PackageNotFoundError(name, version=None)`; `NetworkError(message)`; module constants `PYPI_BASE_URL: str`, `DEFAULT_TIMEOUT: float`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_remote.py`:
```python
"""Unit tests for the PyPI remote fetcher (httpx mocked)."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from peta.core.models import PackageInfo
from peta.core.remote import NetworkError, PackageNotFoundError, get_package

pytestmark = pytest.mark.unit


def _resp(status: int, payload: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    return r


_INFO = {
    "name": "requests",
    "version": "2.31.0",
    "summary": "Python HTTP for Humans.",
    "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org",
    "maintainer": None,
    "license": "Apache-2.0",
    "requires_python": ">=3.8",
    "home_page": "https://requests.readthedocs.io",
    "project_urls": {"Source": "https://github.com/psf/requests"},
    "requires_dist": ["idna", "urllib3", "certifi", "charset-normalizer"],
    "classifiers": ["Development Status :: 5 - Production/Stable"],
    "keywords": "http,requests",
}


@patch("peta.core.remote.httpx")
def test_returns_package_info(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    result = get_package("requests")
    assert isinstance(result, PackageInfo)
    assert result.name == "requests"
    assert result.source == "remote"
    assert len(result.dependencies) == 4
    assert result.files is None
    assert result.keywords == ["http", "requests"]


@patch("peta.core.remote.httpx")
def test_latest_url(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    get_package("requests")
    mock_httpx.get.assert_called_once_with(
        "https://pypi.org/pypi/requests/json", timeout=10.0
    )


@patch("peta.core.remote.httpx")
def test_specific_version_url(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(200, {"info": _INFO, "vulnerabilities": []})
    get_package("requests", version="2.28.0")
    mock_httpx.get.assert_called_once_with(
        "https://pypi.org/pypi/requests/2.28.0/json", timeout=10.0
    )


@patch("peta.core.remote.httpx")
def test_not_found(mock_httpx: MagicMock) -> None:
    mock_httpx.get.return_value = _resp(404)
    with pytest.raises(PackageNotFoundError):
        get_package("nope-xyz")


@patch("peta.core.remote.httpx")
def test_parses_vulnerabilities(mock_httpx: MagicMock) -> None:
    payload = {
        "info": {**_INFO, "keywords": None, "requires_dist": None},
        "vulnerabilities": [
            {"id": "PYSEC-2024-001", "aliases": ["CVE-2024-1"], "summary": "x", "fixed_in": ["1.0.1"]},
        ],
    }
    mock_httpx.get.return_value = _resp(200, payload)
    result = get_package("vuln-pkg")
    assert result.vulnerabilities[0].id == "PYSEC-2024-001"
    assert result.keywords == []
    assert result.dependencies == []


@patch("peta.core.remote.httpx")
def test_network_error(mock_httpx: MagicMock) -> None:
    mock_httpx.RequestError = httpx.RequestError
    mock_httpx.get.side_effect = httpx.ConnectError("refused")
    with pytest.raises(NetworkError):
        get_package("requests")


@patch("peta.core.remote.httpx")
def test_http_status_error(mock_httpx: MagicMock) -> None:
    mock_httpx.HTTPStatusError = httpx.HTTPStatusError
    mock_httpx.RequestError = httpx.RequestError
    resp = _resp(500)
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "boom", request=MagicMock(), response=MagicMock(status_code=500)
    )
    mock_httpx.get.return_value = resp
    with pytest.raises(NetworkError):
        get_package("requests")
```

Note: because `httpx` is patched module-wide, the test re-attaches the real
`httpx.RequestError`/`HTTPStatusError`/`ConnectError` classes so `except` clauses
in the implementation still match.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_remote.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/peta/core/remote.py` (complexity ≤ 5 via helpers)**

```python
"""PyPI JSON API client for remote package metadata."""

from __future__ import annotations

from typing import Any

import httpx

from peta.core.models import PackageInfo, Vulnerability

PYPI_BASE_URL = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10.0


class PackageNotFoundError(Exception):
    """Raised when a package is not found on PyPI."""

    def __init__(self, name: str, version: str | None = None) -> None:
        self.name = name
        self.version = version
        target = f"{name}=={version}" if version else name
        super().__init__(f"Package '{target}' not found on PyPI")


class NetworkError(Exception):
    """Raised when a network request fails."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Network error: {message}")


def _pypi_url(name: str, version: str | None) -> str:
    if version:
        return f"{PYPI_BASE_URL}/{name}/{version}/json"
    return f"{PYPI_BASE_URL}/{name}/json"


def _fetch(name: str, version: str | None) -> dict[str, Any]:
    url = _pypi_url(name, version)
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # noqa: PLR2004
        raise PackageNotFoundError(name, version)

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"PyPI returned HTTP {exc.response.status_code}") from exc

    data: dict[str, Any] = response.json()
    return data


def _parse_keywords(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def _parse_vulnerabilities(raw: list[dict[str, Any]]) -> list[Vulnerability]:
    return [
        Vulnerability(
            id=v["id"],
            aliases=v.get("aliases", []),
            summary=v.get("summary", ""),
            fixed_in=v.get("fixed_in", []),
        )
        for v in raw
    ]


def get_package(name: str, version: str | None = None) -> PackageInfo:
    """Get metadata for a package from PyPI.

    Args:
        name: Package name to look up.
        version: Optional specific version; if ``None`` the latest is fetched.

    Returns:
        A :class:`PackageInfo` with ``source="remote"``.

    Raises:
        PackageNotFoundError: If the package/version does not exist on PyPI.
        NetworkError: If the request fails.
    """
    data = _fetch(name, version)
    info: dict[str, Any] = data["info"]
    return PackageInfo(
        name=info["name"],
        version=info["version"],
        summary=info.get("summary"),
        author=info.get("author"),
        author_email=info.get("author_email"),
        maintainer=info.get("maintainer"),
        license=info.get("license"),
        python_requires=info.get("requires_python"),
        homepage=info.get("home_page"),
        project_urls=info.get("project_urls") or {},
        dependencies=info.get("requires_dist") or [],
        classifiers=info.get("classifiers", []),
        keywords=_parse_keywords(info.get("keywords")),
        files=None,
        vulnerabilities=_parse_vulnerabilities(data.get("vulnerabilities", [])),
        source="remote",
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_remote.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/peta/core/remote.py tests/unit/test_remote.py
git commit -m "feat: add PyPI remote metadata fetcher"
```

---

### Task 6: `core/local.py`

**Files:**
- Create: `src/peta/core/local.py`
- Test: `tests/unit/test_local.py`

**Interfaces:**
- Consumes: `peta.core.models.PackageInfo`.
- Produces: `get_package(name: str) -> PackageInfo`; `PackageNotFoundError(name)`; module attribute `importlib_metadata` (patch target for tests).

- [ ] **Step 1: Write the failing test (mocked only — real-package checks live in integration)**

`tests/unit/test_local.py`:
```python
"""Unit tests for the local metadata fetcher (importlib.metadata mocked)."""

from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from peta.core.local import PackageNotFoundError, get_package

pytestmark = pytest.mark.unit


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


@patch("peta.core.local.importlib_metadata")
def test_parses_urls_keywords_deps_files(mock_meta: MagicMock) -> None:
    md = _msg(Name="rich", Version="13.0.0", Summary="pretty", Keywords="cli, tui")
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


@patch("peta.core.local.importlib_metadata")
def test_not_found_raises(mock_meta: MagicMock) -> None:
    import importlib.metadata as real

    mock_meta.PackageNotFoundError = real.PackageNotFoundError
    mock_meta.distribution.side_effect = real.PackageNotFoundError("x")
    with pytest.raises(PackageNotFoundError):
        get_package("nope-xyz")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_local.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/peta/core/local.py` (complexity ≤ 5 via helpers)**

```python
"""Local package metadata fetcher using importlib.metadata."""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from email.message import Message

from peta.core.models import PackageInfo


class PackageNotFoundError(Exception):
    """Raised when a package is not installed locally."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Package '{name}' is not installed")


def _parse_project_urls(meta: Message) -> dict[str, str]:
    urls: dict[str, str] = {}
    for entry in meta.get_all("Project-URL") or []:
        if ", " in entry:
            label, url = entry.split(", ", 1)
            urls[label.strip()] = url.strip()
    return urls


def _parse_keywords(meta: Message) -> list[str]:
    raw = meta.get("Keywords")
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def get_package(name: str) -> PackageInfo:
    """Get metadata for a locally installed package.

    Args:
        name: Package name to look up.

    Returns:
        A :class:`PackageInfo` with ``source="local"``.

    Raises:
        PackageNotFoundError: If the package is not installed.
    """
    try:
        dist = importlib_metadata.distribution(name)
    except importlib_metadata.PackageNotFoundError as exc:
        raise PackageNotFoundError(name) from exc

    meta = dist.metadata
    files = [str(f) for f in dist.files] if dist.files else None
    return PackageInfo(
        name=meta["Name"],
        version=meta["Version"],
        summary=meta.get("Summary"),
        author=meta.get("Author"),
        author_email=meta.get("Author-email"),
        maintainer=meta.get("Maintainer"),
        license=meta.get("License"),
        python_requires=meta.get("Requires-Python"),
        homepage=meta.get("Home-page"),
        project_urls=_parse_project_urls(meta),
        dependencies=list(dist.requires) if dist.requires else [],
        classifiers=meta.get_all("Classifier") or [],
        keywords=_parse_keywords(meta),
        files=files,
        vulnerabilities=[],
        source="local",
    )
```

If mypy/basedpyright complain that `meta["Name"]` is `Any`/`str | None`, add local
annotations: `name_value: str = meta["Name"]` (and similarly for `Version`) and pass
those in — do not add `# type: ignore` unless a gate genuinely cannot be satisfied
otherwise; if you must, scope it narrowly and note why.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_local.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/peta/core/local.py tests/unit/test_local.py
git commit -m "feat: add local metadata fetcher"
```

---

### Task 7: `output/json.py`

**Files:**
- Create: `src/peta/output/json.py`
- Test: `tests/unit/test_output_json.py`

**Interfaces:**
- Consumes: `PackageInfo`, `Vulnerability`.
- Produces: `format_info(pkg) -> str`, `format_deps(pkg) -> str`, `format_files(pkg) -> str`, `format_versions(name: str, versions: list[dict[str, str]]) -> str`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_output_json.py`:
```python
"""Unit tests for JSON formatters."""

import json

import pytest

from peta.core.models import PackageInfo, Vulnerability
from peta.output.json import format_deps, format_files, format_info, format_versions

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base: dict[str, object] = dict(
        name="requests", version="2.31.0", source="local",
        dependencies=["urllib3"], files=None, vulnerabilities=[],
    )
    base.update(over)
    return PackageInfo(**base)  # type: ignore[arg-type]


def test_info_basic() -> None:
    data = json.loads(format_info(_pkg()))
    assert data["name"] == "requests"
    assert data["source"] == "local"
    assert "urllib3" in data["dependencies"]


def test_info_vulns() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="s", fixed_in=["1.1"])
    data = json.loads(format_info(_pkg(vulnerabilities=[v])))
    assert data["vulnerabilities"][0]["id"] == "PYSEC-1"


def test_deps() -> None:
    data = json.loads(format_deps(_pkg()))
    assert isinstance(data["dependencies"], list)


def test_files_none_and_some() -> None:
    assert json.loads(format_files(_pkg(files=None)))["files"] == []
    got = json.loads(format_files(_pkg(files=["a.py"])))["files"]
    assert got == ["a.py"]


def test_versions() -> None:
    data = json.loads(format_versions("requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}]))
    assert data["name"] == "requests"
    assert len(data["versions"]) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_output_json.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/peta/output/json.py`**

```python
"""JSON output formatters."""

from __future__ import annotations

import json

from peta.core.models import PackageInfo


def format_info(pkg: PackageInfo) -> str:
    """Format :class:`PackageInfo` as a JSON string."""
    data = {
        "name": pkg.name,
        "version": pkg.version,
        "summary": pkg.summary,
        "author": pkg.author,
        "license": pkg.license,
        "python_requires": pkg.python_requires,
        "homepage": pkg.homepage,
        "project_urls": pkg.project_urls,
        "dependencies": pkg.dependencies,
        "vulnerabilities": [
            {"id": v.id, "aliases": v.aliases, "summary": v.summary, "fixed_in": v.fixed_in}
            for v in pkg.vulnerabilities
        ],
        "source": pkg.source,
    }
    return json.dumps(data, indent=2)


def format_deps(pkg: PackageInfo) -> str:
    """Format a package's dependency list as a JSON string."""
    data = {
        "name": pkg.name,
        "version": pkg.version,
        "dependencies": [{"name": d} for d in pkg.dependencies],
    }
    return json.dumps(data, indent=2)


def format_files(pkg: PackageInfo) -> str:
    """Format a package's file list as a JSON string."""
    data = {"name": pkg.name, "version": pkg.version, "files": pkg.files or []}
    return json.dumps(data, indent=2)


def format_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Format a version list as a JSON string."""
    return json.dumps({"name": name, "versions": versions}, indent=2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_output_json.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/peta/output/json.py tests/unit/test_output_json.py
git commit -m "feat: add JSON output formatters"
```

---

### Task 8: `output/tables.py`

**Files:**
- Create: `src/peta/output/tables.py`
- Test: `tests/unit/test_output_tables.py`

**Interfaces:**
- Consumes: `PackageInfo`.
- Produces: `render_info(pkg) -> str`, `render_deps(pkg) -> str`, `render_files(pkg) -> str`, `render_versions(name: str, versions: list[dict[str, str]]) -> str`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_output_tables.py`:
```python
"""Unit tests for Rich renderers."""

import pytest

from peta.core.models import PackageInfo, Vulnerability
from peta.output.tables import render_deps, render_files, render_info, render_versions

pytestmark = pytest.mark.unit


def _pkg(**over: object) -> PackageInfo:
    base: dict[str, object] = dict(
        name="requests", version="2.31.0", source="local",
        summary="Python HTTP for Humans.", homepage="https://x",
        project_urls={"Repo": "https://github.com/psf/requests"},
        dependencies=["urllib3", "idna"], files=None, vulnerabilities=[],
    )
    base.update(over)
    return PackageInfo(**base)  # type: ignore[arg-type]


def test_render_info_string() -> None:
    out = render_info(_pkg())
    assert isinstance(out, str)
    assert "requests" in out
    assert "2.31.0" in out


def test_render_info_vulns() -> None:
    v = Vulnerability(id="PYSEC-1", aliases=[], summary="bad", fixed_in=["2.32.0"])
    assert "PYSEC-1" in render_info(_pkg(vulnerabilities=[v]))


def test_render_deps() -> None:
    assert "urllib3" in render_deps(_pkg())


def test_render_files_some_and_none() -> None:
    assert "__init__.py" in render_files(_pkg(files=["requests/__init__.py"]))
    assert "no file" in render_files(_pkg(files=None)).lower()


def test_render_versions() -> None:
    out = render_versions("requests", [{"version": "2.31.0", "upload_time": "2023-05-22"}])
    assert "2.31.0" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_output_tables.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/peta/output/tables.py` (complexity ≤ 5 via helpers)**

```python
"""Rich text output formatters."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from peta.core.models import PackageInfo


def _to_string(renderable: object) -> str:
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=100).print(renderable)
    return buf.getvalue()


def _info_table(pkg: PackageInfo) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    table.add_row("Name", pkg.name)
    table.add_row("Version", pkg.version)
    for label, value in (
        ("Summary", pkg.summary),
        ("Author", pkg.author),
        ("Maintainer", pkg.maintainer),
        ("License", pkg.license),
        ("Python", pkg.python_requires),
        ("Homepage", pkg.homepage),
    ):
        if value:
            table.add_row(label, value)
    for url_label, url in pkg.project_urls.items():
        table.add_row(f"  {url_label}", url)
    if pkg.dependencies:
        table.add_row("Dependencies", str(len(pkg.dependencies)))
        for dep in pkg.dependencies:
            table.add_row("", f"  {dep}")
    return table


def _vuln_block(pkg: PackageInfo) -> str:
    if not pkg.vulnerabilities:
        return ""
    lines = ["\n⚠ Vulnerabilities:"]
    for v in pkg.vulnerabilities:
        fixed = ", ".join(v.fixed_in) if v.fixed_in else "no fix"
        lines.append(f"  {v.id}: {v.summary} (fix: {fixed})")
    return "\n".join(lines) + "\n"


def render_info(pkg: PackageInfo) -> str:
    """Render :class:`PackageInfo` as a Rich panel string."""
    source_label = "local" if pkg.source == "local" else "pypi"
    panel = Panel(
        _info_table(pkg),
        title=f"{pkg.name} {pkg.version}",
        subtitle=f"source: {source_label}",
    )
    return _to_string(panel) + _vuln_block(pkg)


def render_deps(pkg: PackageInfo) -> str:
    """Render a package's dependencies as a Rich tree string."""
    tree = Tree(f"{pkg.name} {pkg.version}")
    for dep in pkg.dependencies:
        tree.add(dep)
    return _to_string(tree)


def render_files(pkg: PackageInfo) -> str:
    """Render a package's file listing as a string."""
    if not pkg.files:
        return f"No file information available for {pkg.name}.\n"
    lines = [f"{pkg.name} {pkg.version} ({len(pkg.files)} files)\n"]
    lines.extend(f"  {f}" for f in pkg.files)
    return "\n".join(lines) + "\n"


def render_versions(name: str, versions: list[dict[str, str]]) -> str:
    """Render a version list as a Rich table string."""
    table = Table(title=f"{name} versions ({len(versions)} total)")
    table.add_column("Version", style="bold")
    table.add_column("Released")
    for v in versions:
        table.add_row(v["version"], v.get("upload_time", ""))
    return _to_string(table)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_output_tables.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/peta/output/tables.py tests/unit/test_output_tables.py
git commit -m "feat: add Rich output renderers"
```

---

### Task 9: CLI — commands, app, package entry points

**Files:**
- Create: `src/peta/cli/commands/info.py`, `deps.py`, `files.py`, `versions.py`
- Create/Modify: `src/peta/cli/app.py`, `src/peta/__init__.py`, `src/peta/__main__.py`
- Test: `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: core fetchers + output formatters.
- Produces: `peta.cli.app.app` (Typer), `peta.cli.app.run()`, `peta.cli.app._SUBCOMMANDS`; per-command handler funcs `info(...)`, `deps(...)`, `files(...)`, `versions(...)`; command modules expose the patch targets `local_get_package`, `remote_get_package` (info/deps), `remote_get_versions` (versions).

- [ ] **Step 1: Write the failing CLI test**

`tests/unit/test_cli.py`:
```python
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
    base: dict[str, object] = dict(
        name="requests", version="2.31.0", source="local",
        summary="Python HTTP for Humans.", dependencies=["urllib3"],
        files=None, vulnerabilities=[],
    )
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

    @patch("peta.cli.commands.info.vuln_pkg", create=True)
    @patch("peta.cli.commands.info.local_get_package")
    def test_shows_vuln(self, ml: object, _v: object) -> None:
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
        assert "dependencies" in json.loads(runner.invoke(app, ["deps", "requests", "--json"]).output)


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
        assert "files" in json.loads(runner.invoke(app, ["files", "requests", "--json"]).output)


class TestVersions:
    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions(self, m: object) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert "2.31.0" in runner.invoke(app, ["versions", "requests"]).output

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_json(self, m: object) -> None:
        m.return_value = [{"version": "2.31.0", "upload_time": "2023-05-22"}]
        assert isinstance(json.loads(runner.invoke(app, ["versions", "requests", "--json"]).output)["versions"], list)

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_not_found(self, m: object) -> None:
        m.return_value = []
        assert runner.invoke(app, ["versions", "nope"]).exit_code == 1

    @patch("peta.cli.commands.versions.remote_get_versions")
    def test_versions_limit(self, m: object) -> None:
        m.return_value = [{"version": f"1.{i}.0", "upload_time": ""} for i in range(5)]
        out = runner.invoke(app, ["versions", "x", "-n", "2"]).output
        assert "1.4.0" in out and "1.2.0" not in out


class TestRoot:
    def test_help(self) -> None:
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0 and "peta" in r.output.lower()

    def test_version_flag(self) -> None:
        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 0 and r.output.strip().startswith("peta ")

    def test_subcommands_registry(self) -> None:
        assert "info" in _SUBCOMMANDS and "requests" not in _SUBCOMMANDS
```

Remove the `test_shows_vuln` stray `vuln_pkg` patch if it causes trouble — it is
only there as a guard; the real assertion is the `PYSEC-1` output check. If the
extra `@patch(... create=True)` decorator is awkward, delete that one decorator
line and its `_v` parameter.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_cli.py -q`
Expected: FAIL — `peta.cli.app`/command modules not found.

- [ ] **Step 3: Write the four command modules**

`src/peta/cli/commands/info.py`:
```python
"""The ``peta info`` command."""

from __future__ import annotations

import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.local import get_package as local_get_package
from peta.core.models import PackageInfo
from peta.core.remote import NetworkError
from peta.core.remote import PackageNotFoundError as RemoteNotFound
from peta.core.remote import get_package as remote_get_package
from peta.output.json import format_info as json_format
from peta.output.tables import render_info as rich_format


def _parse_package_arg(package: str) -> tuple[str, str | None]:
    if "==" in package:
        name, version = package.split("==", 1)
        return name.strip(), version.strip()
    return package, None


def _resolve(package: str, *, local: bool, remote: bool) -> PackageInfo:
    name, version = _parse_package_arg(package)
    if version:
        return remote_get_package(name, version)
    if remote:
        return remote_get_package(name)
    if local:
        return local_get_package(name)
    try:
        return local_get_package(name)
    except LocalNotFound:
        return remote_get_package(name)


def info(package: str, *, use_json: bool = False, local: bool = False, remote: bool = False) -> None:
    """Show detailed package metadata."""
    try:
        pkg = _resolve(package, local=local, remote=remote)
    except (LocalNotFound, RemoteNotFound):
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
```

`src/peta/cli/commands/deps.py`:
```python
"""The ``peta deps`` command."""

from __future__ import annotations

import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.local import get_package as local_get_package
from peta.core.models import PackageInfo
from peta.core.remote import NetworkError
from peta.core.remote import PackageNotFoundError as RemoteNotFound
from peta.core.remote import get_package as remote_get_package
from peta.output.json import format_deps as json_format
from peta.output.tables import render_deps as rich_format


def _resolve(package: str, *, local: bool, remote: bool) -> PackageInfo:
    if remote:
        return remote_get_package(package)
    if local:
        return local_get_package(package)
    try:
        return local_get_package(package)
    except LocalNotFound:
        return remote_get_package(package)


def deps(package: str, *, use_json: bool = False, local: bool = False, remote: bool = False) -> None:
    """Show a package's declared dependencies."""
    try:
        pkg = _resolve(package, local=local, remote=remote)
    except (LocalNotFound, RemoteNotFound):
        typer.echo(f"Package '{package}' not found.", err=True)
        raise typer.Exit(code=1) from None
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
```

`src/peta/cli/commands/files.py`:
```python
"""The ``peta files`` command."""

from __future__ import annotations

import typer

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.local import get_package as local_get_package
from peta.output.json import format_files as json_format
from peta.output.tables import render_files as rich_format


def files(package: str, *, use_json: bool = False) -> None:
    """List files installed by a local package."""
    try:
        pkg = local_get_package(package)
    except LocalNotFound:
        typer.echo(f"Package '{package}' not found locally.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(json_format(pkg) if use_json else rich_format(pkg))
```

`src/peta/cli/commands/versions.py`:
```python
"""The ``peta versions`` command."""

from __future__ import annotations

from typing import Any

import httpx
import typer
from packaging.version import Version

from peta.core.remote import DEFAULT_TIMEOUT, PYPI_BASE_URL, NetworkError
from peta.output.json import format_versions as json_format
from peta.output.tables import render_versions as rich_format


def get_versions(name: str) -> list[dict[str, str]]:
    """Fetch all published versions for a package from PyPI."""
    url = f"{PYPI_BASE_URL}/{name}/json"
    try:
        response = httpx.get(url, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise NetworkError(str(exc)) from exc

    if response.status_code == 404:  # noqa: PLR2004
        return []

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"PyPI returned HTTP {exc.response.status_code}") from exc

    data: dict[str, Any] = response.json()
    releases: dict[str, list[dict[str, Any]]] = data.get("releases", {})
    result: list[dict[str, str]] = []
    for ver, files in sorted(releases.items(), key=lambda kv: Version(kv[0]), reverse=True):
        upload_time = files[0].get("upload_time", "")[:10] if files else ""
        result.append({"version": ver, "upload_time": upload_time})
    return result


# Patch target used by tests.
remote_get_versions = get_versions


def versions(package: str, *, use_json: bool = False, limit: int = 20) -> None:
    """Show published versions of a package from PyPI."""
    try:
        vers = remote_get_versions(package)
    except NetworkError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    if not vers:
        typer.echo(f"Package '{package}' not found on PyPI.", err=True)
        raise typer.Exit(code=1) from None
    shown = vers[:limit]
    typer.echo(json_format(package, shown) if use_json else rich_format(package, shown))
```

- [ ] **Step 4: Write `src/peta/cli/app.py`**

```python
"""Typer application and command registration."""

from __future__ import annotations

import sys

import typer

from peta import __version__
from peta.cli.commands import deps as deps_mod
from peta.cli.commands import files as files_mod
from peta.cli.commands import info as info_mod
from peta.cli.commands import versions as versions_mod

_SUBCOMMANDS = {"info", "deps", "files", "versions", "--help", "-h", "--version", "-V"}

app = typer.Typer(
    name="peta",
    help="Human-friendly Python package metadata viewer.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"peta {__version__}")
        raise typer.Exit


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(  # noqa: ARG001
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Human-friendly Python package metadata viewer."""


@app.command()
def info(
    package: str = typer.Argument(..., help="Package name (optionally name==version)."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    local: bool = typer.Option(False, "--local", "-l", help="Force local lookup."),
    remote: bool = typer.Option(False, "--remote", "-r", help="Force PyPI lookup."),
) -> None:
    """Show detailed package metadata."""
    info_mod.info(package, use_json=use_json, local=local, remote=remote)


@app.command()
def deps(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    local: bool = typer.Option(False, "--local", "-l", help="Force local lookup."),
    remote: bool = typer.Option(False, "--remote", "-r", help="Force PyPI lookup."),
) -> None:
    """Show a package's declared dependencies."""
    deps_mod.deps(package, use_json=use_json, local=local, remote=remote)


@app.command()
def files(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List files installed by a local package."""
    files_mod.files(package, use_json=use_json)


@app.command()
def versions(
    package: str = typer.Argument(..., help="Package name."),
    use_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    limit: int = typer.Option(20, "--limit", "-n", help="Max versions to show."),
) -> None:
    """Show published versions of a package from PyPI."""
    versions_mod.versions(package, use_json=use_json, limit=limit)


def run() -> None:
    """Entry point; ``peta <package>`` is shorthand for ``peta info <package>``."""
    args = sys.argv[1:]
    if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv.insert(1, "info")
    app()
```

- [ ] **Step 5: Write `__init__.py` and `__main__.py`**

`src/peta/__init__.py`:
```python
"""peta - Human-friendly Python package metadata viewer."""

from __future__ import annotations

from peta._version import __version__

__all__ = ["__version__"]
```

`src/peta/__main__.py`:
```python
"""Entry point for ``python -m peta``."""

from __future__ import annotations

from peta.cli.app import run

run()
```

- [ ] **Step 6: Run the CLI test to verify it passes**

Run: `uv run pytest tests/unit/test_cli.py -q`
Expected: PASS. If `test_shows_vuln`'s extra guard patch errors, delete that one decorator line + `_v` param as noted and re-run.

- [ ] **Step 7: Smoke the real console script**

Run: `uv run peta --version` → prints `peta <version>`.
Run: `uv run peta --help` → lists `info deps files versions`.
Run: `uv run python -m peta --version` → prints `peta <version>`.

- [ ] **Step 8: Commit**

```bash
git add src/peta/cli src/peta/__init__.py src/peta/__main__.py tests/unit/test_cli.py
git commit -m "feat: add Typer CLI, commands, and entry points"
```

---

### Task 10: Integration, e2e, and smoke tiers

**Files:**
- Create: `tests/integration/__init__.py`, `tests/integration/test_local_real.py`, `tests/integration/test_pipeline.py`
- Create: `tests/e2e/__init__.py`, `tests/e2e/test_cli_local.py`, `tests/e2e/test_cli_remote.py`
- Move/Modify: `tests/smoke/__init__.py`, `tests/smoke/test_smoke.py` (relocate the scaffold's `tests/test_smoke.py`)
- Modify: `tests/conftest.py` (shared factory fixture)

**Interfaces:**
- Consumes: the full public API from Tasks 4–9.
- Produces: tiered suites; the offline tiers (smoke+unit+integration) carry coverage.

- [ ] **Step 1: Relocate the smoke test**

```bash
mkdir -p tests/smoke
printf '"""Smoke tests."""\n' > tests/smoke/__init__.py
git mv tests/test_smoke.py tests/smoke/test_smoke.py
```
Overwrite `tests/smoke/test_smoke.py` with:
```python
"""Smoke tests: import and entry point resolve."""

import pytest
from typer.testing import CliRunner

import peta
from peta.cli.app import app

pytestmark = pytest.mark.smoke
runner = CliRunner()


def test_version_attribute() -> None:
    assert isinstance(peta.__version__, str)
    assert peta.__version__


def test_version_command() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("peta ")
```

- [ ] **Step 2: Write `tests/conftest.py` shared factory**

```python
"""Shared fixtures for peta tests."""

from __future__ import annotations

import pytest

from peta.core.models import PackageInfo


@pytest.fixture
def make_package():  # noqa: ANN201
    def _make(**overrides: object) -> PackageInfo:
        base: dict[str, object] = {
            "name": "requests",
            "version": "2.31.0",
            "source": "local",
            "summary": "Python HTTP for Humans.",
            "dependencies": ["urllib3"],
            "files": None,
            "vulnerabilities": [],
        }
        base.update(overrides)
        return PackageInfo(**base)  # type: ignore[arg-type]

    return _make
```

- [ ] **Step 3: Write integration tests (real components, no network)**

`tests/integration/__init__.py` → `"""Integration tests."""\n`

`tests/integration/test_local_real.py`:
```python
"""Integration: core.local against really-installed distributions."""

import pytest

from peta.core.local import PackageNotFoundError, get_package
from peta.core.models import PackageInfo

pytestmark = pytest.mark.integration


def test_reads_installed_typer() -> None:
    result = get_package("typer")
    assert isinstance(result, PackageInfo)
    assert result.name.lower() == "typer"
    assert result.source == "local"
    assert result.version
    assert result.files is not None


def test_reads_installed_rich_dependencies() -> None:
    result = get_package("rich")
    assert isinstance(result.dependencies, list)


def test_missing_raises() -> None:
    with pytest.raises(PackageNotFoundError):
        get_package("definitely-not-installed-xyz-123")
```

`tests/integration/test_pipeline.py`:
```python
"""Integration: resolve -> render wired together, httpx boundary mocked."""

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = pytest.mark.integration
runner = CliRunner()

_PAYLOAD = {
    "info": {
        "name": "flask", "version": "3.0.0", "summary": "web",
        "author": "a", "author_email": None, "maintainer": None,
        "license": "BSD", "requires_python": ">=3.8", "home_page": None,
        "project_urls": {}, "requires_dist": ["werkzeug", "jinja2"],
        "classifiers": [], "keywords": "web,wsgi",
    },
    "vulnerabilities": [],
}


@patch("peta.core.remote.httpx")
def test_remote_info_renders(mock_httpx: MagicMock) -> None:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _PAYLOAD
    mock_httpx.get.return_value = resp
    result = runner.invoke(app, ["info", "flask", "--remote"])
    assert result.exit_code == 0
    assert "flask" in result.output
    assert "3.0.0" in result.output


@patch("peta.core.remote.httpx")
def test_remote_info_json(mock_httpx: MagicMock) -> None:
    import json

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = _PAYLOAD
    mock_httpx.get.return_value = resp
    result = runner.invoke(app, ["info", "flask", "--remote", "--json"])
    assert json.loads(result.output)["name"] == "flask"
```

- [ ] **Step 4: Write e2e tests**

`tests/e2e/__init__.py` → `"""End-to-end tests."""\n`

`tests/e2e/test_cli_local.py` (deterministic, no network — uses installed pkgs):
```python
"""E2E: full CLI against locally-installed packages (no network)."""

import json

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = pytest.mark.e2e
runner = CliRunner()


def test_info_local_pkg() -> None:
    result = runner.invoke(app, ["info", "typer", "--local"])
    assert result.exit_code == 0
    assert "typer" in result.output.lower()


def test_files_local_pkg() -> None:
    result = runner.invoke(app, ["files", "rich"])
    assert result.exit_code == 0
    assert ".py" in result.output


def test_info_local_json() -> None:
    result = runner.invoke(app, ["info", "typer", "--local", "--json"])
    assert json.loads(result.output)["source"] == "local"


def test_deps_local_pkg() -> None:
    result = runner.invoke(app, ["deps", "rich", "--local"])
    assert result.exit_code == 0
```

`tests/e2e/test_cli_remote.py` (opt-in — real PyPI):
```python
"""E2E: full CLI against real PyPI. Opt-in (network).

Run with: uv run pytest -m e2e_remote  (deselected by default).
"""

import os

import pytest
from typer.testing import CliRunner

from peta.cli.app import app

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("PETA_E2E_NETWORK") != "1",
        reason="network e2e disabled; set PETA_E2E_NETWORK=1 to run",
    ),
]
runner = CliRunner()


def test_versions_httpx_remote() -> None:
    result = runner.invoke(app, ["versions", "httpx", "-n", "5"])
    assert result.exit_code == 0
    assert "httpx" in result.output.lower()


def test_info_remote_requests() -> None:
    result = runner.invoke(app, ["info", "requests", "--remote"])
    assert result.exit_code == 0
    assert "requests" in result.output.lower()
```

- [ ] **Step 5: Run the full offline suite**

Run: `uv run pytest -q` (network e2e is skipped by default via the env guard)
Expected: PASS, no errors. Note the number of skipped tests (the remote e2e ones).

- [ ] **Step 6: Commit**

```bash
git add tests/
git commit -m "test: add tiered smoke/unit/integration/e2e suites"
```

---

### Task 11: Green all gates + coverage 99 + copier anchor

**Files:**
- Modify (as needed): `pyproject.toml` (`per-file-ignores`, coverage config), any source file needing a conformance touch-up.

**Interfaces:**
- Produces: a fully green baseline ready for PR.

- [ ] **Step 1: Gate ruff with a diff BEFORE autofix (skill gotcha #1)**

Run: `uv run ruff check --diff src tests`
Review every proposed change. Nothing should delete a `typer.echo`/logic line. Then:
Run: `uv run ruff check --fix src tests` and `uv run ruff format src tests`
Re-run `uv run ruff check src tests` → expected: no errors. Add a narrowly-scoped `per-file-ignore` (not a blanket `noqa`) only for a deliberate, documented pattern.

- [ ] **Step 2: Type-check**

Run: `uv run mypy src` → expected: no errors.
Run: `uv run basedpyright src` → expected: no errors.
Fix genuine typing issues in source (prefer annotations/casts over `# type: ignore`).

- [ ] **Step 3: Complexity gate**

Run: `uv run ruff check --select C901 src` → expected: no errors (every function ≤ 5). If any function trips it, extract a helper (the `core`/`output` modules already do this) and re-run relevant unit tests.

- [ ] **Step 4: Coverage to real 99%**

Run: `uv run pytest --cov=peta --cov-report=term-missing -q`
Read the `Missing` column. For each uncovered line in `src/peta/**`, add a real
test to the appropriate tier (e.g. `versions` HTTP-error branch, `deps` network
error, empty-releases path). Do NOT add `# pragma: no cover` to hit the number
(only the scaffold's pre-existing `if __name__` whitelist stands). Re-run until
`TOTAL` ≥ 99% on the offline tiers. If a line is genuinely untestable offline,
stop and surface it rather than excluding it.

- [ ] **Step 5: Docs build**

Run: `uv run sphinx-build -W -b html docs docs/_build/html`
Expected: exits 0 (warnings-as-errors). Fix any autodoc import error (usually a
stale module path in `modules.rst`). Confirm `docs/superpowers/**` is NOT in the
built output: `ls docs/_build/html | grep -i superpowers` → no match.

- [ ] **Step 6: Build the package**

Run: `uv build`
Expected: builds sdist + wheel with a version derived from git (not `0.0.0`
unless untagged — acceptable on a feature branch). Confirm no `_version.py` edit
is staged.

- [ ] **Step 7: Copier update-anchor gate (skill gotcha / step 5)**

Read the `_commit` value from `.copier-answers.yml`. Run:
`uvx copier@latest update --vcs-ref=<that _commit> --pretend --trust --defaults`
Expected: prints `Keeping template version …<_commit>` (nothing to re-apply). If it
wants to re-apply changes, the reconciliation diverged — inspect and fix before PR.
(Run this only after committing; `--pretend` refuses on a dirty tree.)

- [ ] **Step 8: Full local matrix (optional but recommended)**

Run: `uv run --locked tox run -e style` then `uv run --locked tox run`
Expected: green. If `taplo format --check` fails (skill gotcha #10), run
`uv run taplo format pyproject.toml` and re-run.

- [ ] **Step 9: Final commit**

```bash
git add -A
git commit -m "chore: satisfy strict gates and reach 99% coverage"
```

---

## Self-Review

**Spec coverage:**
- Target structure → Tasks 2, 4–9. ✎ Removals (Task 2), package files (Tasks 4–9).
- Drop `DependencyNode`/`download_count`/`dependent_count` → Task 4 (models omit them; unit test omits them).
- Deps into `[project]`, drop extras/`peta-tui`, entry point `:run` → Task 1.
- `requires-python >=3.14` across all tools/classifiers → Task 1.
- Dynamic version, no literal → Task 9 (`__init__` imports `_version`), Task 1 (`uv sync` generates it), smoke/CLI tests assert `startswith("peta ")` not `0.1.0`.
- Full conformance: `from e`/`from None`, narrowed `except httpx.RequestError`, typed `importlib` access, complexity helpers → Tasks 5, 6, 8, 9, 11.
- Error taxonomy + exit codes → Tasks 5, 6, 9 (tests assert exit 1/2).
- Tiered tests (smoke/unit/integration/e2e), offline 99%, opt-in remote → Tasks 4–10, gate in 11.
- DDD docs first → Task 3; Sphinx exclude of spec/plan → Task 3 step 6 + verified Task 11 step 5.
- copier anchor gate → Task 11 step 7.
- No reference name/URL anywhere → Global Constraints; all embedded code/docs are name-free.

**Placeholder scan:** No `TBD`/`TODO`/"handle edge cases"/"similar to Task N". All code steps carry real code; the only intentional `TODO` references are instructions to *delete* the template's planted `TODO @` lines (README, modules.rst).

**Type consistency:** command modules expose `local_get_package`/`remote_get_package`/`remote_get_versions` (patched identically in Task 9 tests); `get_package(name, version=None)` signature consistent across remote impl (Task 5) and info command (Task 9); `render_*`/`format_*`/`_resolve` names consistent between output tasks (7, 8) and CLI (9); `_SUBCOMMANDS`, `run`, `app` names consistent between `app.py` (Task 9) and tests (Tasks 9, 10).
