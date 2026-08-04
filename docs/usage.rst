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

Color
-----

``peta`` colors Rich output when stdout is a terminal. Disable it with the
root ``--no-color`` flag or the ``NO_COLOR`` environment variable; both take
precedence over TTY detection. ``--json`` output is always plain. See
:doc:`configuration` for the ``NO_COLOR`` variable.

Vulnerabilities
----------------

``peta info`` enriches its vulnerability list from `OSV.dev
<https://api.osv.dev/>`_ by default, merging OSV results with any PyPI
advisories and deduping entries that share an id or alias. This lookup is
best-effort: network failures leave the PyPI-only results in place and never
change the exit code. Pass ``--no-osv`` to skip it entirely.

Download and dependent counts
------------------------------

``peta info`` also shows a package's last-month download count from
`pypistats.org <https://pypistats.org/>`_ and its dependent count from
`libraries.io <https://libraries.io/>`_ by default. Both lookups are
best-effort: a network failure simply omits the corresponding field and
never changes the exit code. The dependent count additionally requires a
``LIBRARIES_IO_API_KEY`` (see :doc:`configuration`); without one it is
omitted with no request made. Pass ``--no-stats`` to skip both lookups.

Resolution
----------

For ``info`` and ``deps``, ``peta`` checks the local environment first and
falls back to PyPI. Force a source with ``--local``/``-l`` or
``--remote``/``-r``. A ``name==version`` argument is supported by ``info``
only and always queries PyPI (it cannot be combined with ``--local``).
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
