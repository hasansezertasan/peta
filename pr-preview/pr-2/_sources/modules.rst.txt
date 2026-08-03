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

.. automodule:: peta.core.local

.. automodule:: peta.core.remote

Output (``peta.output``)
----------------------------

.. automodule:: peta.output.tables

.. automodule:: peta.output.json

CLI (``peta.cli``)
----------------------------

.. automodule:: peta.cli.app

.. automodule:: peta.cli.commands.info

.. automodule:: peta.cli.commands.deps

.. automodule:: peta.cli.commands.files

.. automodule:: peta.cli.commands.versions
