Architecture
============

``peta`` is organised into two layers.

CLI (``peta.cli``)
------------------

``peta.cli.app`` defines the Typer application and five commands
(``info``, ``compare``, ``deps``, ``files``, and ``versions``). ``run()`` rewrites
``sys.argv`` so a bare ``peta <package>`` becomes ``peta info <package>``.
Each command in ``peta.cli.commands`` orchestrates a fetch and a render.

Rendering lives under this same layer, in ``peta.cli.output``:

* ``peta.cli.output.tables`` — Rich table and tree renderers returning strings.
* ``peta.cli.output.json`` — versioned JSON envelope formatters.
* ``peta.cli.output.markdown`` — Markdown string formatters.
* ``peta.cli.output.text`` — plain-text string formatters.
* ``peta.cli.output.render`` — central format dispatch for command results.
* ``peta.cli.output.errors`` — structured parser-validation error rendering.
* ``peta.cli.output.selection`` — format selection and handler failure rendering.
* ``peta.cli.output.console`` — shared console/color helpers.
* ``peta.cli.output.changes`` — shared wording for semantic change records.

These renderers are typer-free (plain string builders); ``peta.cli``
commands call them and print/echo the result.

Core (``peta.core``)
--------------------

* ``peta.core.models`` — package, vulnerability, and dependency-tree models.
* ``peta.core.output`` — typed output-envelope, query, source, and message models.
* ``peta.core.local`` — reads installed metadata via ``importlib.metadata``.
* ``peta.core.http`` — the one pooled ``httpx`` client every source shares.
* ``peta.core.cache`` — on-disk response cache, TTL vocabulary, and offline mode.
* ``peta.core.concurrency`` — runs independent lookups together, in order.
* ``peta.core.remote`` — fetches from the PyPI JSON API.
* ``peta.core.resolve`` — chooses local or remote package metadata.
* ``peta.core.deptree`` — builds recursive declared-metadata dependency trees.
* ``peta.core.enrich`` — coordinates optional vulnerability and statistics data.
* ``peta.core.providers`` — the provider seam and built-in source adapters.
* ``peta.core.osv`` — queries the OSV vulnerability API.
* ``peta.core.stats`` — queries download and dependent-count APIs.
* ``peta.core.vulns`` — merges and deduplicates vulnerability records.
* ``peta.core.changes`` — the shared change vocabulary for every comparison.
* ``peta.core.diff`` — the package-and-release engine built on that vocabulary.
* ``peta.core.validation`` — validates decoded external API response fields.

Comparisons
-----------

Several commands put two sides next to each other: ``compare`` today, and on
the roadmap installed against registry, wheel against sdist, a recorded
snapshot against now, one release across two indexes, and release history.
They are separate commands rather than one ``diff`` command with source
adapters, because each takes different inputs and flags, and one command
would have to accept the union of all of them.

What they must not do is describe differences separately.
``peta.core.changes`` holds the one vocabulary — groups, stable change kinds,
``before``/``after`` values, the ``expected`` flag, and the "could not
compare" record — and knows nothing about how a command gathers its sides. A
new comparison adds its kinds there and reuses ``peta.cli.output.changes`` to
render them, instead of defining a parallel model that would drift.

The ``expected`` flag separates a real difference from one that follows from
what was compared. Two releases always ship differently named files with
different digests, and a platform wheel is expected to differ from an sdist;
comparing the same release across indexes, or a snapshot with now, expects
neither. The comparison decides what it expects, and the renderers summarize
expected differences instead of listing them, so they never bury the ones
that need attention.

Error model
-----------

``PackageNotFoundError`` (exit 1), ``NetworkError`` (exit 2), and
``OfflineError`` (exit 2) are raised by the core layer and mapped to exit codes
by the command handlers. ``OfflineError`` is kept separate from
``NetworkError``: under ``--offline`` nothing failed, peta was told not to use
the network and does not hold the answer. JSON output
also renders these failures as structured, versioned envelopes.
