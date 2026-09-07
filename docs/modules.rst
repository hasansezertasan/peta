.. A 7-character "=" underline (the length of "Modules") is treated as a
   merge-conflict separator by ``git diff --check`` / ``check-merge-conflict``;
   keep this underline longer than the title to avoid the false positive.

Modules
=========

An overview of the packages that make up ``peta``.
The API reference below is generated automatically from the source docstrings.

Core (``peta.core``)
----------------------------

.. automodule:: peta.core.models

.. automodule:: peta.core.output

.. automodule:: peta.core.local

.. automodule:: peta.core.remote

.. automodule:: peta.core.resolve

.. automodule:: peta.core.deptree

.. automodule:: peta.core.enrich

.. automodule:: peta.core.providers.base

.. automodule:: peta.core.providers.builtin

.. automodule:: peta.core.osv

.. automodule:: peta.core.stats

.. automodule:: peta.core.vulns

.. automodule:: peta.core.validation

CLI (``peta.cli``)
----------------------------

.. automodule:: peta.cli.app

.. automodule:: peta.cli.state

.. automodule:: peta.cli.output.console

.. automodule:: peta.cli.output.tables

.. automodule:: peta.cli.output.json

.. automodule:: peta.cli.output.markdown

.. automodule:: peta.cli.output.text

.. automodule:: peta.cli.output.render

.. automodule:: peta.cli.output.errors

.. automodule:: peta.cli.output.selection

.. automodule:: peta.cli.commands.info

.. automodule:: peta.cli.commands.compare

.. automodule:: peta.cli.commands.deps

.. automodule:: peta.cli.commands.files

.. automodule:: peta.cli.commands.versions
