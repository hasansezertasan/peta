# Design: peta feature expansion (5 capabilities)

- **Date:** 2026-08-04
- **Branch:** `feat/migrate-source` (stacked onto PR #2)
- **Status:** Approved design — building all five, sequentially, one commit set per feature
- **Python floor:** stays `>=3.14`. No new runtime dependencies (all new I/O uses the
  existing `httpx`; requirement parsing uses the existing `packaging`).

## Overview

Five capabilities the reference README advertised but never implemented, now built
for real, in this order (small→large, minimizing rework since several touch
`PackageInfo` / `core.remote` / the renderers):

1. Real color output + `--no-color`
2. OSV vulnerabilities (second source, merged with PyPI's)
3. Download + dependent counts (pypistats + libraries.io)
4. `compare <a> <b>` command
5. Recursive dependency tree + `deps --why`

Every feature: strict gates stay green (ruff ALL, mypy, basedpyright 0/0, ty,
pyrefly, zuban, vulture, complexity ≤5, coverage ≥99% on offline tiers), tiered
tests, docs updated (reality-only, now that these are real), no version literal,
no private reference-repo name/URL anywhere.

---

## Feature 1 — Real color output + `--no-color`

**Finding:** peta currently never emits color — renderers build strings via
`Console(file=StringIO(), force_terminal=False)`, which strips styles. So `--no-color`
is only meaningful once color actually renders.

**Design:**
- New `src/peta/output/console.py`:
  - `resolve_color(*, no_color: bool) -> bool` — `no_color` flag wins; else honor the
    `NO_COLOR` env var (any non-empty value → off); else `sys.stdout.isatty()`.
  - `render(renderable: object, *, color: bool, width: int = 100) -> str` —
    `Console(file=StringIO(), force_terminal=color, no_color=not color, width=width)`;
    returns the captured string (ANSI when `color=True`, plain otherwise).
- `output/tables.py`: `_to_string` and every `render_*` gain a keyword `color: bool`
  and delegate to `console.render(..., color=color)`.
- CLI: a `--no-color` global option on the root callback. Resolve once into a small
  `CliState` dataclass stored on `ctx.obj`; each command takes `ctx: typer.Context`,
  reads `ctx.obj.color`, and passes it to its handler → renderer.
- Scope: Rich path only; `--json` output is always plain.

**Testing:** `CliRunner` output is not a TTY → auto-plain, so existing
`"x" in output` assertions hold. New: `--no-color` forces plain; `NO_COLOR=1`
forces plain; `render(..., color=True)` contains an ESC (`\x1b`) sequence.

---

## Feature 2 — OSV vulnerabilities

**Design:**
- New `src/peta/core/osv.py`:
  - `get_vulnerabilities(name: str, version: str | None = None) -> list[Vulnerability]`
    — POST `https://api.osv.dev/v1/query` with
    `{"package": {"name": name, "ecosystem": "PyPI"}, "version": version}` (omit
    `version` when `None`). Map each OSV vuln → `Vulnerability` (id, aliases, summary,
    `fixed_in` from the affected ranges' `fixed` events, `severity` from the CVSS
    `severity` list when present).
  - On any `httpx.RequestError` / non-200 / malformed body → return `[]` (OSV is
    supplementary enrichment; it must never fail the command). Constants
    `OSV_API_URL`, reuse `DEFAULT_TIMEOUT` from `core.remote`.
- Merge: a `core.vulns.merge_vulnerabilities(existing, osv)` helper dedups by
  vulnerability identity (same `id`, or overlapping `aliases`), preferring the entry
  that carries a severity.
- `info` flow: after resolving `PackageInfo`, unless `--no-osv` is given, enrich
  `pkg.vulnerabilities` with OSV results (merged, deduped). `--no-osv` global-ish
  option on `info` (and later `compare`).
- Renderer: the existing vuln block also prints `severity` when set.

**Testing:** mock `httpx.post`; assert mapping (id/aliases/fixed_in/severity),
graceful `[]` on network error, and dedup/merge with a PyPI vuln sharing an alias.
An opt-in e2e hits real OSV (network-gated).

---

## Feature 3 — Download + dependent counts

**Design:**
- Re-add to `PackageInfo` (dropped during migration):
  `download_count: int | None = None`, `dependent_count: int | None = None`.
- New `src/peta/core/stats.py`:
  - `get_download_count(name: str) -> int | None` — GET
    `https://pypistats.org/api/packages/{name}/recent` → `data.last_month`. No API key.
    Returns `None` on failure/404.
  - `get_dependent_count(name: str, *, api_key: str | None) -> int | None` — GET
    `https://libraries.io/api/pypi/{name}?api_key=...` → `dependents_count`. Requires
    an API key; returns `None` when the key is absent or the request fails.
  - `api_key` comes from the `LIBRARIES_IO_API_KEY` environment variable, read via a
    tiny `stats.libraries_io_api_key() -> str | None` helper.
- `info` flow: unless `--no-stats`, enrich `download_count`/`dependent_count` (network,
  best-effort — failures leave the field `None`). `--no-stats` option on `info`
  (and `compare`).
- Renderers: `render_info` adds "Downloads (last month)" and "Dependents" rows when
  the values are set. `format_info` JSON includes `download_count`/`dependent_count`.

**Testing:** mock `httpx.get`; pypistats happy path + 404→None; libraries.io with key
happy path, without key → None, failure → None. Env-var helper tested with
monkeypatched environ. Renderer/JSON show the counts. Opt-in e2e hits the real APIs.

---

## Feature 4 — `compare <a> <b>`

**Design:**
- Extract package resolution: move `info._resolve`/`_resolve_versioned`/
  `_parse_package_arg` into `src/peta/core/resolve.py` (`resolve_package(arg, *, local,
  remote) -> PackageInfo`), so both `info` and `compare` share one resolver. `info.py`
  becomes a thin caller.
- New `src/peta/cli/commands/compare.py`: `compare(a, b, *, use_json, local, remote,
  color, no_osv, no_stats)` — resolve both (with the same OSV/stats enrichment as
  `info`), then render.
- `output/tables.py`: `render_compare(a, b, *, color) -> str` — a Rich table with
  columns `Field | <a> | <b>` over version, summary, author, license, python_requires,
  dependency count, downloads, dependents, vulnerability count.
- `output/json.py`: `format_compare(a, b) -> str` → `{"packages": [ {..}, {..} ]}`.
- CLI: `compare` command with `--json`, `--local/-l`, `--remote/-r`, `--no-color`,
  `--no-osv`, `--no-stats`.

**Testing:** CliRunner with both fetches mocked — table shows both names/versions;
`--json` yields two package objects; not-found in either → exit 1; network → exit 2.

---

## Feature 5 — Recursive dependency tree + `deps --why`

**Design:**
- Re-add `DependencyNode` to `models.py` (dropped during migration): `name`,
  `version_spec`, `installed_version`, `children`, `circular`.
- New `src/peta/core/deptree.py`:
  - `build_tree(name, *, local, remote, max_depth=10) -> DependencyNode` — resolve the
    package (shared resolver), parse each `requires_dist` entry with
    `packaging.requirements.Requirement` (name + specifier; **skip entries with an
    unsatisfied environment marker** — extras/`python_version` etc.), and recurse.
    Cycle detection via a visited-name set on the current path → mark `circular=True`
    and stop. `max_depth` bounds runaway graphs (log/annotate when truncated).
  - `find_why(root, target) -> list[list[str]]` — all root→target name paths.
- `deps` command: default output becomes the **recursive tree** (was flat top-level).
  `deps <pkg> --why <target>` prints the dependency chains explaining why `<target>`
  is pulled in. New `--depth N` (default 10) bounds recursion.
- Renderers: `render_dep_tree(node, *, color)` (Rich `Tree`, recursive, circular nodes
  marked `(circular)`); `render_why(target, paths, *, color)`. `format_dep_tree(node)`
  JSON (nested `{name, version_spec, installed_version, circular, children:[...]}`).
- Resolution cost: a small in-run cache (name→PackageInfo) avoids refetching shared
  deps; the offline/unit tests mock the resolver so no network is hit.

**Testing:** unit tests on `build_tree` with a mocked resolver — linear chain, shared
diamond dep (cache hit), a cycle (`circular=True`, no infinite loop), `max_depth`
truncation, marker-guarded entries skipped. `find_why` returns correct chains
(including multiple paths). CLI tests for tree render, `--why`, `--depth`, `--json`.

---

## Cross-cutting

- **Error model:** new network sources (OSV, pypistats, libraries.io) are *best-effort
  enrichment* — they degrade to empty/`None`, never changing `info`/`compare` exit
  codes. Only the primary local/PyPI resolution drives exit 1/2 (unchanged).
- **Flags summary added:** `--no-color` (root), `--no-osv` / `--no-stats`
  (`info`, `compare`), `--why <target>` / `--depth N` (`deps`).
- **Config:** `LIBRARIES_IO_API_KEY` env var (dependents only). Documented; absence
  degrades gracefully.
- **Docs:** `README.md` + `docs/usage.rst` updated per feature (these are now real);
  a new `docs/configuration.rst` documents `NO_COLOR` and `LIBRARIES_IO_API_KEY`.
- **Tests:** each feature adds unit + integration coverage to keep offline TOTAL ≥99%;
  network-dependent paths get opt-in e2e (`PETA_E2E_NETWORK`).
- **Gates before each push:** full `uv run --locked tox run -e style` AND
  `tox run -e prek` (typos/markdownlint live there), plus the standard checks.

## Constraints (unchanged)

- No version literal in hand-written source; `_version.py` never edited.
- Never name the internal reference repository or its URL anywhere.
- Conventional Commits; no AI-authorship trailers.
