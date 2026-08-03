# peta

<!-- TODO @hasansezertasan: Make it work, make it right, make it fast. -->
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

> Human-friendly Python package metadata viewer

-----

## Table of Contents

- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Support](#support-heart)
- [Motivation](#motivation)
- [Features](#features)
- [About](#about)
- [Author](#author-person_with_crown)
- [Analysis](#analysis)
- [Contributing](#contributing-heart)
- [Development](#development-toolbox)
- [Releasing](#releasing)
- [Credits](#credits)
- [License](#license-scroll)
- [Changelog](#changelog-memo)

## Screenshots

<!-- TODO @hasansezertasan: Add screenshots or a demo GIF, or remove this section. -->

## Installation

```console
pip install peta
```

## Usage

### CLI

```bash
peta version
peta info
```

### TUI

```bash
peta-tui
```

An interactive terminal user interface displays project information. Press 'q' to exit.

### Debugging

Debug your application in VS Code using the provided launch configurations:

- **Current File**: Debug the currently open Python file.
- **Tests**: Debug pytest runs.
- **Attach**: Attach to a running process (e.g., web app with debugpy).
- **Web App/CLI/TUI/GUI**: Debug specific entry points (if enabled).
- **With Profiling**: Debug while profiling with scalene (if profiling enabled).

Select a configuration from the Run and Debug panel in VS Code.

## Support :heart:

If you have any questions or need help, feel free to open an issue on the [GitHub repository][peta].

## Motivation

<!-- TODO @hasansezertasan: Explain why this project exists and what problem it solves, or remove this section. -->

## Features

- **CLI Application**: Command-line interface built with Typer
- **TUI Application**: Terminal user interface built with Textual
- **Type Safety**: Full type hints checked by mypy, basedpyright, ty, pyrefly, and zuban
- **Code Quality**: Comprehensive linting and formatting with ruff, plus architecture-contract enforcement with import-linter
- **Testing**: pytest with coverage reporting and parallel execution
- **Documentation**: Sphinx documentation with the Shibuya theme, GitHub Pages deployment, and live per-PR documentation previews
- **CI/CD**: Automated testing, building, and publishing across multiple platforms
- **Security**: CodeQL, OpenSSF Scorecard, dependency review, secret scanning (gitleaks), dependency auditing (pip-audit), GitHub Actions static analysis (zizmor — a blocking prek/CI gate plus a Security-tab dashboard, over hardened least-privilege workflows), and a CycloneDX SBOM attached to every release
- **Managed `.gitignore`**: kept in sync with the upstream [github/gitignore](https://github.com/github/gitignore) templates by [cobo](https://github.com/hasansezertasan/cobo), with a weekly drift check
- **Modern Python**: uv for dependency management, hatch for building

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

<!-- xc-heading -->
## Development :toolbox:

Clone the repository and cd into the project directory:

```sh
git clone https://github.com/hasansezertasan/peta
cd peta
```

The commands below can also be executed using the [xc task runner](https://xcfile.dev/), which combines the usage instructions with the actual commands. Simply run `xc`, it will pop up an interactive menu with all available tasks.

### `install`

Install the dependencies:

```sh
uv sync
```

### `style`

Run the style checks:

```sh
uv run --locked tox run -e style
```

### `ci`

Run the CI pipeline:

```sh
uv run --locked tox run
```

### `docs-build`

Build the documentation site:

```sh
uv run --locked tox run -e docs-build
```

### `docs-server`

Start the live-reloading docs server:

```sh
uv run --locked tox run -e docs-server
```

### `docs-linkcheck`

Check the documentation for broken links (also runs weekly in CI):

```sh
uv run --locked tox run -e docs-linkcheck
```

## Releasing

Versioning and releases are automated with [release-please](https://github.com/googleapis/release-please), driven by [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) PR titles squash-merged into `main`. release-please maintains a release PR that bumps the version and `CHANGELOG.md`; merging it tags the release and publishes to PyPI. See the [Contributing Guidelines](./.github/CONTRIBUTING.md#releasing) for the commit conventions and the one-time [Repository setup](./.github/CONTRIBUTING.md#repository-setup-one-time) (squash-merge settings, Actions permissions, release immutability, and PyPI trusted publishing).

## Credits

This package was created with [Copier](https://github.com/copier-org/copier) and the [hasansezertasan/copier-pyproject](https://github.com/hasansezertasan/copier-pyproject) project template.

## License :scroll:

This project is licensed under the [MIT License](https://spdx.org/licenses/MIT.html).

## Changelog :memo:

For a detailed list of changes, please refer to the [CHANGELOG](./CHANGELOG.md).

<!-- Refs -->
[author]: https://github.com/hasansezertasan
[peta]: https://github.com/hasansezertasan/peta
