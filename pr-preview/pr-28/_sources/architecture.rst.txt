Architecture
============

``peta`` is organised into two layers.

CLI (``peta.cli``)
------------------

``peta.cli.app`` defines the Typer application and four commands
(``info``, ``deps``, ``files``, ``versions``). ``run()`` rewrites
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

* ``peta.core.models`` — ``PackageInfo`` and ``Vulnerability`` dataclasses.
* ``peta.core.local`` — reads installed metadata via ``importlib.metadata``.
* ``peta.core.remote`` — fetches from the PyPI JSON API with ``httpx``.

Error model
-----------

``PackageNotFoundError`` (exit 1) and ``NetworkError`` (exit 2) are raised
by the core layer and mapped to exit codes by the command handlers.
