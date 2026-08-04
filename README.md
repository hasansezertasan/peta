# peta

[![CI](https://github.com/hasansezertasan/peta/actions/workflows/ci.yml/badge.svg)](https://github.com/hasansezertasan/peta/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/hasansezertasan/peta)](https://codecov.io/gh/hasansezertasan/peta)
[![Documentation Status](https://img.shields.io/github/deployments/hasansezertasan/peta/github-pages?label=docs)](https://hasansezertasan.github.io/peta)
[![PyPI - Version](https://img.shields.io/pypi/v/peta.svg)](https://pypi.org/project/peta)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/peta.svg)](https://pypi.org/project/peta)
[![License - MIT](https://img.shields.io/github/license/hasansezertasan/peta.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/hasansezertasan/peta?style=social)](https://github.com/hasansezertasan/peta/stargazers)
[![Latest Commit](https://img.shields.io/github/last-commit/hasansezertasan/peta)](https://github.com/hasansezertasan/peta)

[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![linting - Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hasansezertasan/peta/badge)](https://scorecard.dev/viewer/?uri=github.com/hasansezertasan/peta)
[![GitHub Tag](https://img.shields.io/github/tag/hasansezertasan/peta?include_prereleases=&sort=semver&color=black)](https://github.com/hasansezertasan/peta/releases/)

[![Downloads](https://pepy.tech/badge/peta)](https://pepy.tech/project/peta)
[![Downloads/Month](https://pepy.tech/badge/peta/month)](https://pepy.tech/project/peta)
[![Downloads/Week](https://pepy.tech/badge/peta/week)](https://pepy.tech/project/peta)

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
peta compare requests httpx   # side-by-side metadata comparison
peta requests --json          # machine-readable output
```

### Flags

| Flag | Applies to | Meaning |
|------|-----------|---------|
| `--json` | all | JSON output |
| `--local` / `-l` | info, deps | force local lookup |
| `--remote` / `-r` | info, deps | force PyPI lookup |
| `--limit` / `-n` | versions | max versions to show (default 20) |
| `--no-color` | (root) | disable colored output (also via `NO_COLOR`) |
| `--version` / `-V` | (root) | print version and exit |

## License

MIT
