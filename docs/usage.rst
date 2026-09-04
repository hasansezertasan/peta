Usage
=====

``peta`` reads package metadata from your local environment or from the
PyPI JSON API and prints it with Rich formatting. Use ``--format`` with
``rich``, ``text``, ``json``, or ``markdown`` on any command. ``--json`` remains
an alias for ``--format json``.

Commands
--------

The command and option reference is generated from the Typer application, so it
always reflects the installed version of ``peta``. A bare ``peta <package>`` is
shorthand for ``peta info <package>``.

.. peta-cli::

Color
-----

``peta`` colors Rich output when stdout is a terminal. Disable it with the
root ``--no-color`` flag or the ``NO_COLOR`` environment variable; both take
precedence over TTY detection. Text, JSON, and Markdown output is always plain. See
:doc:`configuration` for the ``NO_COLOR`` variable.

Vulnerabilities
----------------

``peta info`` enriches its vulnerability list from `OSV.dev
<https://api.osv.dev/>`_ by default, merging OSV results with any PyPI
advisories and deduping entries that share an id or alias. This lookup is
best-effort: failures leave the PyPI-only results in place, add a source-specific
enrichment warning, and never change the exit code. Pass ``--no-osv`` to skip it
entirely.

Download and dependent counts
------------------------------

``peta info`` also shows a package's last-month download count from
`pypistats.org <https://pypistats.org/>`_ and its dependent count from
`libraries.io <https://libraries.io/>`_ by default. Both lookups are
best-effort: a failure omits the corresponding field, adds a source-specific
enrichment warning, and never changes the exit code. The dependent count
additionally requires a ``LIBRARIES_IO_API_KEY`` (see :doc:`configuration`);
without one it is omitted with no request made. Pass ``--no-stats`` to skip
both lookups. JSON envelopes expose these failures as structured ``warnings``
and mark the overall result ``partial``. See :doc:`output-contract`.

Dependency tree
---------------

``peta deps <package>`` prints the package's full recursive dependency tree
(not just its direct requirements), resolving each dependency the same way
``info`` does. Requirements whose environment marker is not satisfied (e.g.
an ``extra`` that is not requested, or a ``python_version`` constraint that
excludes the running interpreter) are skipped. A dependency that reappears
on its own ancestor path is shown once more and marked ``(circular)`` rather
than being expanded again. Recursion stops at ``--depth`` (default ``10``)
levels; deeper dependencies are omitted.

The tree is a metadata view, not a full dependency resolution: each
dependency is expanded from its currently-installed or latest-published
metadata (a version specifier such as ``foo<2`` narrows what is *shown*, not
which release is expanded), and dependencies gated behind an ``extra`` are
not activated. ``--why`` searches only the tree built at the current
``--depth``, so raise ``--depth`` if a target is deeper than the default.

Pass ``--why <target>`` to show every chain of dependencies that pulls
``<target>`` into the tree, instead of the full tree, e.g. ``peta deps flask
--why certifi``. If ``<target>`` is not present anywhere in the tree, ``peta``
prints a message to stderr and exits with code 1.

Resolution
----------

For ``info``, ``deps``, and ``compare``, ``peta`` checks the local
environment first and falls back to PyPI. Force a source with
``--local``/``-l`` or ``--remote``/``-r``. A ``name==version`` argument is
supported by ``info`` only and always queries PyPI (it cannot be combined
with ``--local``). ``files`` is local-only; ``versions`` is PyPI-only.
``compare`` resolves and enriches both packages the same way ``info`` does,
including the ``--no-osv``/``--no-stats`` flags.

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

Failures from optional OSV, pypistats, and Libraries.io enrichment sources are
reported as warnings and retain exit code ``0``.

With JSON output, fatal errors use the same versioned envelope as successful
results and appear in the ``errors`` array. The exit codes above are unchanged,
so scripts should inspect both the process status and the envelope.
