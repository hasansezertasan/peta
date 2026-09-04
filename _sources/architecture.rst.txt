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

* ``peta.cli.output.tables`` — Rich renderers returning strings.
* ``peta.cli.output.json`` — JSON string formatters.
* ``peta.cli.output.console`` — shared console/color helpers.

These renderers are typer-free (plain string builders); ``peta.cli``
commands call them and print/echo the result.

Core (``peta.core``)
--------------------

* ``peta.core.models`` — package, vulnerability, and dependency-tree models.
* ``peta.core.local`` — reads installed metadata via ``importlib.metadata``.
* ``peta.core.remote`` — fetches from the PyPI JSON API with ``httpx``.
* ``peta.core.resolve`` — chooses local or remote package metadata.
* ``peta.core.deptree`` — builds recursive declared-metadata dependency trees.
* ``peta.core.enrich`` — coordinates optional vulnerability and statistics data.
* ``peta.core.osv`` — queries the OSV vulnerability API.
* ``peta.core.stats`` — queries download and dependent-count APIs.
* ``peta.core.vulns`` — merges and deduplicates vulnerability records.
* ``peta.core.validation`` — validates decoded external API response fields.

Error model
-----------

``PackageNotFoundError`` (exit 1) and ``NetworkError`` (exit 2) are raised
by the core layer and mapped to exit codes by the command handlers.
