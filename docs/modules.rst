.. A 7-character "=" underline (the length of "Modules") is treated as a
   merge-conflict separator by ``git diff --check`` / ``check-merge-conflict``;
   keep this underline longer than the title to avoid the false positive.

Modules
=========

An overview of the packages that make up ``peta``.
The API reference below is generated automatically from the source docstrings.

Core (``peta.core``)
----------------------------

Always-included infrastructure.

.. automodule:: peta.core.config

.. automodule:: peta.core.dirs

.. automodule:: peta.core.logging_setup

Utilities (``peta.utils``)
----------------------------

Shared helper functions.

.. automodule:: peta.utils

CLI (``peta.cli``)
----------------------------

Typer command-line interface exposing ``version`` and ``info`` commands.

.. automodule:: peta.cli.app


.. TODO @hasansezertasan: Document your own modules here as the project grows.
