"""Sphinx configuration for peta.

See https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# Make documentation-only adapters importable by Sphinx extensions.
sys.path.insert(0, str(Path(__file__).resolve().parent / "_ext"))

# -- Project information -----------------------------------------------------
project = "peta"
author = "Hasan Sezer Tasan"
# Reproducible builds: honor SOURCE_DATE_EPOCH (https://reproducible-builds.org/)
# so the stamped copyright year is a function of the source (e.g. the last
# commit date, as exported by the CI docs steps) rather than the clock. Local
# `tox` runs leave it unset and fall back to the current year below.
_source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
_build_date = (
    datetime.fromtimestamp(int(_source_date_epoch), tz=UTC)
    if _source_date_epoch
    else datetime.now(tz=UTC)
)
copyright = f"{_build_date:%Y}, Hasan Sezer Tasan"  # ruff: ignore[builtin-variable-shadowing]

# -- General configuration ---------------------------------------------------
extensions = [
    "cli_reference",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.viewcode",
    "sphinx.ext.githubpages",  # emits .nojekyll so GitHub Pages serves _static/
    "sphinx_design",
    "sphinx_copybutton",
    "sphinx_togglebutton",
    "sphinx_paramlinks",
    "auto_pytabs.sphinx_ext",
    "myst_parser",
    "sphinx_last_updated_by_git",
]

# Both reStructuredText and (via MyST) Markdown source files are supported.
source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "superpowers/**"]

# autosectionlabel can emit duplicate-label warnings across documents; the
# document prefix keeps them unique, so no blanket suppression is needed.
autosectionlabel_prefix_document = True

# -- Autodoc / Napoleon ------------------------------------------------------
autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_typehints = "description"
autoclass_content = "both"
napoleon_google_docstring = True
napoleon_numpy_docstring = False

# -- auto-pytabs -------------------------------------------------------------
# Keep the version tabs in sync with this project's supported Python range
# (requires-python >= 3.10, classifiers/CI up to 3.14). auto-pytabs otherwise
# defaults to (3, 7), which would mislabel the rendered examples.
auto_pytabs_min_version = (3, 10)
auto_pytabs_max_version = (3, 14)

# -- Intersphinx -------------------------------------------------------------
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}


# -- HTML output (Shibuya theme) ---------------------------------------------
# https://shibuya.lepture.com/
html_theme = "shibuya"
html_title = "peta"
html_theme_options = {
    "accent_color": "amber",
    "github_url": "https://github.com/hasansezertasan/peta",
}

# -- Versioned docs switcher (ADR-027) ---------------------------------------
# tools/build_docs.py writes docs/_static/versions.json into each CI build from
# the gh-pages directory listing. When present, feed the Shibuya theme's native
# version switcher (components/nav-versions.html) via html_context. Absent (e.g.
# a local ``tox -e docs-build`` run) the switcher simply does not render.
# GitHub Pages serves a project site under ``/<repo>/``, so switcher links are
# rooted at that base path (not the domain root); a custom root domain would set
# ``_switcher_base = "/"`` instead.
_switcher_base = "/peta/"
_versions_file = Path(__file__).parent / "_static" / "versions.json"
if _versions_file.exists():
    _versions = json.loads(_versions_file.read_text(encoding="utf-8"))
    _current = os.environ.get("DOCS_BUILD_VERSION_SLUG") or _versions.get("latest", "")
    html_context = {
        "current_version": _current,
        "versions": [
            ["latest", f"{_switcher_base}latest/"],
            *([slug, f"{_switcher_base}{slug}/"] for slug in _versions["versions"]),
        ],
    }
