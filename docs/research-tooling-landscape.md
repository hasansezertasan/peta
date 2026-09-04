# Python package-inspection tooling landscape

_Research date: 2026-09-03. Local assessment: the repository state checked out on that date. External facts are sourced from first-party documentation or project repositories; recommendations explicitly marked **Inference** are conclusions drawn from those facts._

## Progress update — 2026-09-04

Peta v0.1.1 shipped the first correctness work identified by this report:

- modern `License-Expression` support and synchronized command/module documentation;
- runtime validation for PyPI, OSV, pypistats, and Libraries.io responses; and
- structured, source-specific warnings for partial enrichment failures.

The next milestone is the v0.2 architectural foundation: a versioned output
contract, provider interfaces, shared transport/cache behavior, and migration of
version discovery to the PyPI Index API. The observations below remain the
dated research snapshot; this update records delivery without rewriting that
original assessment.

## Executive summary

`peta` has a credible niche as a human-friendly, read-only “package dossier”: one command combines installed or PyPI metadata, dependencies, versions, files, popularity signals, known vulnerabilities, comparisons, and JSON. The closest tools each cover only part of that workflow: pip and uv focus on an environment, pipdeptree on dependency graphs, pip-audit on vulnerability auditing, and pip-licenses on license inventory. Cargo’s `cargo info` remains the clearest cross-ecosystem model for a concise local-or-registry package view.

The strongest roadmap is not to become another package manager. It is to make the dossier more trustworthy and useful before broadening it:

1. inspect the user-selected environment instead of implicitly inspecting the environment in which `peta` itself runs;
2. replace the deprecated PyPI `releases` source used by `versions`;
3. distinguish declared requirements from an actually resolved dependency graph and surface conflicts;
4. add release-artifact and provenance signals;
5. turn comparison into a real semantic package/version diff;
6. version the JSON contract and add cache/concurrency controls.

## What `peta` is today

The public interface has five views: `info`, `deps`, `files`, `versions`, and `compare`; a bare package name aliases `info`. `info` and `compare` resolve locally first unless the user forces PyPI, and all commands offer JSON ([CLI source](../src/peta/cli/app.py), [README](https://github.com/hasansezertasan/peta#readme)).

The core combines:

- installed Core Metadata and installed file names via `importlib.metadata` ([local reader](../src/peta/core/local.py));
- PyPI project or release JSON ([remote reader](../src/peta/core/remote.py));
- OSV results merged with PyPI advisories ([enrichment](../src/peta/core/enrich.py), [merge logic](../src/peta/core/vulns.py));
- last-month downloads from pypistats.org and an optional Libraries.io dependent count ([statistics client](../src/peta/core/stats.py));
- a recursively expanded metadata tree and root-to-target `--why` paths ([tree builder](../src/peta/core/deptree.py)); and
- Rich terminal rendering plus an ad hoc JSON representation ([text output](../src/peta/cli/output/tables.py), [JSON output](../src/peta/cli/output/json.py)).

Two important limitations follow directly from the implementation:

- “Local” means the Python environment running `peta`: `importlib.metadata.distribution(name)` is called without a selectable path or interpreter ([local reader](../src/peta/core/local.py)). This conflicts with the recommended isolated `uvx`, `uv tool`, and `pipx` installation workflow in the [README](https://github.com/hasansezertasan/peta#readme): an isolated tool cannot reliably see packages in the project environment the user probably intends to inspect.
- The dependency tree is explicitly a metadata view, not a resolver: each child is expanded from its installed or latest PyPI metadata even when that selected version does not satisfy the parent specifier ([tree builder](../src/peta/core/deptree.py), [usage note](usage.rst)). This is useful for exploration, but `installed_version` is a misleading label for a remotely selected latest release.

At the time of assessment there were also two visible consistency bugs. The project declared the modern SPDX-style `license = "MIT"` in [pyproject.toml](../pyproject.toml), but both readers consumed only the legacy `License`/`license` field; local and remote queries therefore rendered `license: null`. The architecture document also said there were four commands and omitted `compare`, while the architecture and module docs omitted newer core modules. Both findings were corrected in v0.1.1 ([local reader](../src/peta/core/local.py), [remote reader](../src/peta/core/remote.py), [architecture](architecture.rst), [module index](modules.rst)).

The implementation also uses the project-level PyPI JSON `releases` mapping to list versions ([versions command](../src/peta/cli/commands/versions.py)). PyPI now marks that field deprecated and recommends the Index API for all distributions or versions ([PyPI JSON API](https://docs.pypi.org/api/json/)).

## Comparable tools and transferable ideas

### Direct comparators

- **pip** supplies `pip show` for installed metadata and files, `pip index versions` for index releases and target compatibility filters, and `pip inspect` for an environment report. The `pip inspect` JSON schema is declared stable, includes an explicit schema version, environment marker context, install origin, installer, and whether a distribution was directly requested ([`pip show`](https://pip.pypa.io/en/stable/cli/pip_show/), [`pip index`](https://pip.pypa.io/en/stable/cli/pip_index/), [`pip inspect` schema](https://pip.pypa.io/en/stable/reference/inspect-report/)).
- **uv** exposes installed-package inspection, environment verification, and project/environment dependency trees. Its tree supports reverse views, pruning, target Python/platform filtering, universal resolution, and compressed wheel sizes; its CLI also supports offline/cache and explicit project/interpreter selection ([inspection guide](https://docs.astral.sh/uv/pip/inspection/), [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-tree)).
- **pipdeptree** displays installed dependency relationships and reports conflicts/cycles; it supports reverse queries, JSON, Mermaid and Graphviz output, summary statistics, and—now—trees resolved from an index or read from a PEP 751 lock ([project README](https://github.com/tox-dev/pipdeptree)).

### Adjacent comparators

- **pip-audit** audits environments, projects, requirements and lock files using PyPI or OSV; it offers fix/dry-run behavior, ignore rules, CI-oriented exit codes, JSON/Markdown, and CycloneDX SBOM output ([project README](https://github.com/pypa/pip-audit)).
- **pip-licenses** inventories installed-package licenses and can emit Markdown, reStructuredText, HTML, JSON, CSV and other formats, include license/notice files, and enforce allow/deny policies ([project README](https://github.com/raimon49/pip-licenses)).
- **Cargo `info`** uses one package specification for workspace-local or registry metadata, accepts explicit versions and alternate registries, and supports offline/locked behavior ([Cargo Book](https://doc.rust-lang.org/cargo/commands/cargo-info.html)). This is especially relevant because `peta` describes itself as “`cargo info` for Python.”
- **deps.dev** is an adjacent data service rather than a CLI. Its v3 API provides PyPI package/version metadata, requirements, resolved dependency graphs, licenses, advisories, project links, attestations, and project status ([deps.dev API](https://docs.deps.dev/api/v3/)). It is a possible optional enrichment source, not a replacement for authoritative PyPI metadata.

## Comparative feature matrix

“Yes” means an intentional, documented feature, not something that can only be assembled with shell scripting. “Partial” means a narrower form than the row describes.

| Capability | peta | pip | uv | pipdeptree | pip-audit | pip-licenses | cargo info |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Concise human package dossier | **Yes** | Partial | Partial | No | No | No | **Yes** |
| Installed metadata | **Yes** | **Yes** | **Yes** | Partial | Partial | Partial | Workspace only |
| Remote registry metadata | **Yes** | Versions only | No comparable dossier | Tree/index focused | Advisory focused | No | **Yes** |
| Explicit release selection | **Yes** (`==`) | Index target filters | Resolver/project inputs | **Yes** from index/lock | Via inputs | Installed only | **Yes** |
| Recursive dependency graph | **Yes**, declared/latest view | Environment report only | **Yes**, resolved | **Yes**, resolved/installed | Resolution for audit | No | Separate `cargo tree` |
| Reverse/why view | **Yes** | No | **Yes** | **Yes** | No | No | Separate `cargo tree` |
| Conflict/cycle reporting | Cycles only | `pip check` | `uv check` | **Yes** | Collection failures | No | No |
| Vulnerability view | **Yes** | No | Audit command | No | **Yes**, specialist | No | No |
| Popularity/dependent signals | **Yes** | No | No | No | No | No | Partial registry fields |
| Artifact size/hash/yanked view | No | Partial via index | Tree sizes | Installed size | SBOM component data | No | No |
| Provenance/attestation view | No | Installed origin | Partial | No | No | No | No |
| Side-by-side comparison | **Yes** | No | No | No | No | No | No |
| Select environment/interpreter/path | No | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | Workspace/toolchain |
| Alternate/private index | No | **Yes** | **Yes** | **Yes** | **Yes** | N/A | **Yes** |
| Versioned machine-readable contract | No | **Yes** (`inspect`) | JSON on selected commands | **Yes** | **Yes** | **Yes** | No |
| Graph/SBOM export | JSON tree only | No | Text tree | Mermaid/Graphviz/JSON | CycloneDX/JSON | No | Separate commands |

Sources for the matrix are the linked first-party documents in the comparator sections and the local source links in “What `peta` is today.”

## Prioritized recommendations

Effort is a relative estimate for this repository: **S** (a few focused changes), **M** (a new vertical slice), **L** (architecture or resolver-level work).

### P0 — make existing claims dependable

#### 0. Fix user-visible metadata and documentation regressions (**S**, immediate value)

Read `License-Expression` before falling back to legacy `License`, add a regression fixture using Metadata 2.4+, and refresh the command/module documentation from the implemented application. Core Metadata deprecates `License` in favor of SPDX `License-Expression` and makes the two fields mutually exclusive ([Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/)).

**Inference:** this small fix should precede broader metadata work because `null` license output undermines trust in the central “package dossier” promise, and stale command docs hide an existing differentiator.

#### 1. Add explicit environment targeting (**M**, very high value)

Add `--python PATH`, `--path SITE_PACKAGES` (repeatable), and a clearly documented selection order; consider auto-discovering `.venv` only when unambiguous. Include the selected interpreter/path and marker environment in text and JSON output. The Python API already exposes installed metadata, requirements, files, file sizes/hashes, entry points, and import-to-distribution mappings ([`importlib.metadata` docs](https://docs.python.org/3/library/importlib.metadata.html)); pip’s stable inspect report demonstrates the useful environment/origin fields and `--path` behavior ([`pip inspect`](https://pip.pypa.io/en/stable/cli/pip_inspect/), [schema](https://pip.pypa.io/en/stable/reference/inspect-report/)).

**Inference:** this is the highest-impact fix because the documented isolated-install path otherwise makes local-first behavior silently inspect the wrong environment. It also makes the Python 3.14 runtime floor less restrictive for inspecting projects that run on older Python versions.

#### 2. Move `versions` to the PyPI Index API (**S–M**, high correctness value)

Use `GET /simple/<project>/` with `Accept: application/vnd.pypi.simple.v1+json`, derive versions/files from filenames or the API’s `versions` data, and retain the release JSON endpoint only for per-release metadata. The Simple Repository JSON model includes file hashes, `requires-python`, yanked status/reason, size, upload time, Core Metadata availability, and provenance URLs ([standard](https://packaging.python.org/en/latest/specifications/simple-repository-api/), [PyPI implementation](https://docs.pypi.org/api/index-api/)).

**Inference:** creating a reusable `IndexClient` now prevents `versions` breakage and becomes the foundation for artifact inspection, compatibility filters, private indexes, and caching.

#### 3. Make dependency semantics explicit and conflict-aware (**M** for validation, **L** for full resolution)

In the near term, rename `installed_version` to `selected_version`, record `source`, and mark every node as `satisfied`, `conflicting`, `unresolved`, `circular`, or `depth_limited`. Add `--extra`, `--python-version`, `--platform`, and a visible “declared metadata tree” label. In the longer term, offer a truly resolved mode through a resolver/library or an optional deps.dev backend; deps.dev documents a resolved PyPI graph endpoint, while uv and pipdeptree show the user expectation for resolved trees ([deps.dev API](https://docs.deps.dev/api/v3/), [uv tree](https://docs.astral.sh/uv/reference/cli/#uv-tree), [pipdeptree](https://github.com/tox-dev/pipdeptree)).

**Inference:** do not silently replace the lightweight metadata tree. A fast declared view and a slower resolved view answer different questions; naming them is better product design than pretending they are equivalent.

### P1 — differentiate on package trust and decision support

#### 4. Add a release-artifact “preflight” section/command (**M**, very high differentiation)

For each release, summarize wheel/sdist availability, wheel tags, total/download sizes, SHA-256, upload time, yanked state/reason, `Requires-Python`, Core Metadata availability, and provenance/attestation presence. PyPI’s Simple API exposes these fields ([Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)); the Integrity API exposes PEP 740 provenance objects and Trusted Publisher identities ([PyPI Integrity API](https://docs.pypi.org/api/integrity/)).

Suggested UX:

```text
peta artifacts cryptography==46.0.1
peta info cryptography --artifacts
```

**Inference:** a compact “Can I install it, what will I download, is it yanked, and is its publication attributable?” view is both useful and less duplicated by pip/uv than generic environment management.

#### 5. Turn `compare` into a semantic diff (**M**, high value)

Keep side-by-side display, but add changed-only output for dependencies (added/removed/specifier/marker changes), Python floor, extras, license expression, vulnerabilities/fixes, artifacts, yanked state, and release age. Explicitly document same-project version comparison, which the parser already accepts even though examples focus on comparing two project names ([argument parser](../src/peta/core/resolve.py), [comparison renderer](../src/peta/cli/output/tables.py)).

Suggested UX:

```text
peta compare django==5.2 django==6.0 --changes-only
peta compare ruff uv --format markdown
```

**Inference:** comparison is `peta`’s clearest unique feature in this set. Deepening it is likely more defensible than adding package-manager actions.

#### 6. Track modern Core Metadata instead of a hand-picked legacy subset (**M**, medium-high value)

Add at least `Metadata-Version`, `License-Expression`, `License-File`, `Provides-Extra`, `Import-Name`/`Import-Namespace`, entry points, and installed origin (`direct_url.json`, installer, requested/direct status). Core Metadata 2.6 defines the current fields and deprecates free-form `License` in favor of SPDX `License-Expression` ([Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/)); the Direct URL standard records VCS commit, requested revision, archive hashes, and editable installs ([Direct URL Data Structure](https://packaging.python.org/en/latest/specifications/direct-url-data-structure/)).

**Inference:** model the raw standardized metadata separately from optional enrichments. That reduces churn when metadata revisions add fields and makes “source of truth” visible.

### P2 — improve automation and ecosystem reach

#### 7. Publish a versioned output contract and unified `--format` (**M**, high automation value)

Add a top-level `schema_version`, tool version, query/target environment, source attribution per field, warnings, and partial-failure details. Support `--format rich|text|json|markdown` rather than separate booleans; preserve `--json` as an alias. Pip’s `inspect` contract explicitly versions backward-incompatible changes and requires consumers to check that version ([pip inspect JSON specification](https://pip.pypa.io/en/stable/reference/inspect-report/)).

**Inference:** best-effort enrichments should distinguish “zero/none” from “not queried” and “query failed”; otherwise automation can mistake missing evidence for a clean result.

#### 8. Add HTTP reuse, bounded concurrency, and persistent caching (**M**, medium-high value)

Reuse an `httpx.Client`, fetch independent enrichments concurrently with a small bound, batch vulnerability queries for trees/comparisons, and cache immutable release metadata long-term while caching latest/stats briefly. OSV provides `querybatch` for multiple package versions ([OSV API](https://google.github.io/osv.dev/api/), [`querybatch`](https://google.github.io/osv.dev/post-v1-querybatch/)); pypistats asks regular clients to cache and notes that its data updates daily ([pypistats API](https://pypistats.org/api/)). Add `--offline`, `--refresh`, and cache provenance to output.

**Inference:** this will matter most after artifact data and tree vulnerability overlays increase request fan-out; establish the client/cache seam before that expansion.

#### 9. Support PEP 503/691-compatible indexes and credentials safely (**L**, medium enterprise value)

Add `--index-url`, configuration-file/env support, standard name normalization, and a credential strategy that never prints secrets. Pip, uv, Cargo, pipdeptree, and pip-audit all support non-default registries/indexes in their relevant workflows ([`pip index`](https://pip.pypa.io/en/stable/cli/pip_index/), [uv CLI](https://docs.astral.sh/uv/reference/cli/), [Cargo info](https://doc.rust-lang.org/cargo/commands/cargo-info.html), [pip-audit](https://github.com/pypa/pip-audit)).

**Inference:** build this on the Index API abstraction from recommendation 2. A PyPI-only release-details client will otherwise need a second redesign.

#### 10. Add ecosystem-friendly exports selectively (**M**, medium value)

Mermaid/DOT export for dependency views and CycloneDX export for resolved environments are established interoperability paths: pipdeptree documents Mermaid/Graphviz/JSON renderers, pip-audit emits CycloneDX, and CycloneDX represents components, dependencies, licenses, and vulnerabilities ([pipdeptree](https://github.com/tox-dev/pipdeptree), [pip-audit](https://github.com/pypa/pip-audit), [CycloneDX overview](https://cyclonedx.org/specification/overview/)).

**Inference:** avoid inventing a custom graph or SBOM schema. Export only when graph completeness is known and label incomplete declared-metadata graphs as such.

## Smaller additions worth considering

- Batch `peta info pkg1 pkg2 ...` and stdin input; pip and uv already let users inspect multiple installed packages ([`pip show`](https://pip.pypa.io/en/stable/cli/pip_show/), [uv inspection](https://docs.astral.sh/uv/pip/inspection/)).
- `--open homepage|docs|source|issues|pypi` and OSC-8 terminal hyperlinks, using normalized well-known project URL labels. PyPI describes how project URLs are grouped and when they are verified ([PyPI project metadata](https://docs.pypi.org/project_metadata/)).
- Installed file totals and hashes. `importlib.metadata.PackagePath` exposes `size` and `hash`, not just the path currently rendered by `peta` ([Python docs](https://docs.python.org/3/library/importlib.metadata.html)).
- A concise health summary: direct/transitive counts, max depth, conflicts, cycles, vulnerable nodes, artifact size, and unknowns. Pipdeptree’s first-party README shows this pattern for package counts, depth, conflicts, cycles, licenses, and size ([pipdeptree](https://github.com/tox-dev/pipdeptree)).
- Optional popularity context (daily/weekly/monthly trend and measurement caveat), not a single unlabeled quality score. Pypistats excludes known mirrors but includes CI downloads, so downloads are an uncertain usage proxy ([pypistats API](https://pypistats.org/api/), [FAQ](https://pypistats.org/faqs)).
- Reassess the `>=3.14` runtime floor after environment targeting lands. The project currently declares only Python 3.14 ([pyproject.toml](../pyproject.toml)), which prevents installation inside older project environments even though package inspection is particularly valuable there. **Inference:** lowering the floor is useful only if supported by a real CI/test matrix; environment targeting is the safer first step.

## What not to prioritize

These are **inferences** from the overlap analysis:

- **Installation, upgrades, and lock generation:** pip and uv are mature owners of mutating package-management workflows. `peta` is more coherent and safer as an inspector.
- **A full vulnerability-policy engine:** keep the useful package-level signal and deep-link to advisories, but leave remediation, ignores, requirements/lock auditing, CI enforcement, and SBOM vulnerability workflows to pip-audit.
- **A full license-compliance engine:** display normalized license expressions and files, but leave environment-wide allow/deny policy and notice collection to pip-licenses.
- **A TUI or web UI before correctness work:** the current Rich output already addresses readability; environment targeting, stable APIs, dependency truthfulness, and provenance produce more user value first.
- **An opaque “package score”:** downloads, dependents, vulnerabilities, provenance, release age, and maintenance signals have different caveats. Show evidence with source/time, and let users apply their own policy.

## Suggested sequence

1. **v0.1.1 — completed:** modern license parsing, documentation synchronization, response validation, and structured enrichment failures.
2. **v0.2 — architectural foundation:** versioned output/error contract; provider interfaces; shared HTTP, cache, concurrency, and offline behavior; Index API client and migrated `versions`.
3. **v0.3 — local inspection:** explicit environment targeting; installed origin/integrity; environment-wide dossier.
4. **v0.4 — package trust:** modern Core Metadata; artifact/provenance preflight; installed-versus-registry drift; reproducible snapshots.
5. **Later — representations and graphs:** local artifacts and project/lock inputs; explicit declared-versus-resolved dependency modes; conflicts, vulnerability overlays, and standard graph/SBOM exports.

That sequence preserves `peta`’s small read-only character while making its differentiator sharper: a fast, attractive, evidence-rich answer to “What is this Python package, what exactly would I get, and how does it compare?”
