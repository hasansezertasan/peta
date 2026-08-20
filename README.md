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

<<<<<<< before updating
`peta` is an end-user CLI tool; install it into an isolated environment:

```bash
# Run without installing
uvx peta requests

# Install as a tool
uv tool install peta
pipx install peta
```

On macOS/Linux via [Homebrew](https://github.com/hasansezertasan/homebrew-tap):

```bash
brew install hasansezertasan/tap/peta
```

On Windows via [Scoop](https://github.com/hasansezertasan/scoop-bucket):

```bash
scoop bucket add hasansezertasan https://github.com/hasansezertasan/scoop-bucket
scoop install peta
```

**Requires:** Python 3.14+

## Usage

```bash
peta requests                 # info (local first, falls back to PyPI)
peta info requests            # explicit info
peta info requests==2.31.0    # a specific version from PyPI
peta deps flask               # recursive dependency tree
peta deps flask --why certifi # why is certifi pulled in?
peta files rich               # files installed locally
peta versions httpx           # published versions on PyPI
peta compare requests httpx   # side-by-side metadata comparison
peta requests --json          # machine-readable output
```

### Flags
=======
`peta` is a standalone end-user tool whose primary command is `peta`. Install it into an isolated environment:

```console
uv tool install peta
```

Or run it without installing with `uvx peta`. See the [installation docs](https://hasansezertasan.github.io/peta/installation.html) for pipx and from-source options.

## Usage

### CLI

```bash
peta version
peta info
```

## Support :heart:

If you have any questions or need help, feel free to open an issue on the [GitHub repository][peta].

## Motivation

<!-- TODO @hasansezertasan: Explain why this project exists and what problem it solves, or remove this section. -->

## Features

- **CLI Application**: Command-line interface built with Typer

## About

<!-- TODO @hasansezertasan: Add background/context about the project, or remove this section. -->

## Author :person_with_crown:

This project is maintained by [Hasan Sezer Tasan][author], It's me :wave:

## Analysis

- [Snyk Python Package Health Analysis](https://snyk.io/advisor/python/peta)
- [Libraries.io - PyPI](https://libraries.io/pypi/peta)
- [Safety DB](https://data.safetycli.com/packages/pypi/peta)
- [PePy Download Stats](https://www.pepy.tech/projects/peta)
- [PyPI Download Stats](https://pypistats.org/packages/peta)
- [Pip Trends Download Stats](https://piptrends.com/package/peta)
- [PyPI Map Dependency Graph](https://pypimap.com/package/peta)

## Contributing :heart:

Any contributions are welcome! Please follow the [Contributing Guidelines](./.github/CONTRIBUTING.md) to contribute to this project.

## Development :toolbox:

See the [Contributing Guidelines](./.github/CONTRIBUTING.md#your-first-code-contribution)
for local setup, the common development tasks (exposed via [mise](https://mise.jdx.dev)),
building and previewing the documentation, and the VS Code debugging configurations.

## Releasing

Versioning and releases are automated with [release-please](https://github.com/googleapis/release-please), driven by [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) PR titles squash-merged into `main`. release-please maintains a release PR that bumps the version and `CHANGELOG.md`; merging it tags the release and publishes to PyPI. See the [Contributing Guidelines](./.github/CONTRIBUTING.md#releasing) for the commit conventions, and the one-time [Repository setup](./docs/maintaining/setup.rst) guide (squash-merge settings, Actions permissions, release immutability, and PyPI trusted publishing) for maintainers.

## Credits

This package was created with [Copier](https://github.com/copier-org/copier) and the [hasansezertasan/copier-pyproject](https://github.com/hasansezertasan/copier-pyproject) project template.

## License :scroll:

This project is licensed under the [MIT License](https://spdx.org/licenses/MIT.html).
>>>>>>> after updating

| Flag | Applies to | Meaning |
| ------ | ----------- | --------- |
| `--json` | all | JSON output |
| `--local` / `-l` | info, deps | force local lookup |
| `--remote` / `-r` | info, deps | force PyPI lookup |
| `--limit` / `-n` | versions | max versions to show (default 20) |
| `--why <target>` | deps | show why `<target>` is a dependency |
| `--depth <n>` | deps | max recursion depth (default 10) |
| `--no-color` | (root) | disable colored output (also via `NO_COLOR`) |
| `--version` / `-V` | (root) | print version and exit |

## License

MIT
