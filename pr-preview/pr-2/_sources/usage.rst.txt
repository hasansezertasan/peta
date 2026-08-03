Usage
=====

``peta`` reads package metadata from your local environment or from the
PyPI JSON API and prints it with Rich formatting. Add ``--json`` to any
command for machine-readable output.

Commands
--------

.. list-table::
   :header-rows: 1

   * - Command
     - Description
   * - ``peta <package>``
     - Shorthand for ``peta info <package>``.
   * - ``peta info <package>``
     - Detailed metadata (local first, PyPI fallback).
   * - ``peta deps <package>``
     - Declared dependencies of a package.
   * - ``peta files <package>``
     - Files installed by a local package.
   * - ``peta versions <package>``
     - Published versions from PyPI.

Resolution
----------

For ``info`` and ``deps``, ``peta`` checks the local environment first and
falls back to PyPI. Force a source with ``--local``/``-l`` or
``--remote``/``-r``. A ``name==version`` argument always queries PyPI.
``files`` is local-only; ``versions`` is PyPI-only.

Exit codes
----------

.. list-table::
   :header-rows: 1

   * - Code
     - Meaning
   * - ``0``
     - Success.
   * - ``1``
     - Package not found.
   * - ``2``
     - Network or PyPI HTTP error.
