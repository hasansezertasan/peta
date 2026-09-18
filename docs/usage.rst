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

Caching and offline use
------------------------

Successful responses are cached on disk, so repeat queries cost a local read
rather than a request. Package metadata and version listings are kept for an
hour, and download and dependent counts for a few. A ``name==version`` lookup
is *not* kept longer, even though a published release's metadata is settled:
the same PyPI response carries the package's advisory list, and an advisory can
be published against a release at any time. Where a source supplies a
validator, peta revalidates a stale entry conditionally, so an unchanged answer
costs a round trip but no body.

Entries are removed once they pass a retention bound, so the cache does not
grow without limit. Only files peta itself wrote are ever deleted, which
matters if ``--cache-dir`` points somewhere that already holds your own data.

Only ``200`` responses are stored. An error describes the moment, not the
package, so caching one would turn a transient outage into a persistent wrong
answer. Credentials never reach the cache: the Libraries.io API key travels in
the query string and is stripped before a URL is hashed or recorded, and only
an allowlist of response headers is kept.

Root flags control it:

.. list-table::
   :header-rows: 1

   * - Flag
     - Effect
   * - ``--offline``
     - Contact no source. Answers come from the cache, including entries past
       their TTL, which are reported as ``cached`` rather than withheld. A
       fatal lookup the cache cannot answer exits ``2`` with an
       ``offline_unavailable`` error naming the URL; an optional enrichment
       source that cannot be answered stays a non-fatal warning.
   * - ``--refresh``
     - Ignore stored entries and replace them with fresh responses. Cannot be
       combined with ``--offline``, which would ask peta both to refetch
       everything and to make no requests.
   * - ``--cache-dir``
     - Where to keep the cache. Defaults to ``$PETA_CACHE_DIR``, then
       ``$XDG_CACHE_HOME/peta``, then ``~/.cache/peta``
       (``%LOCALAPPDATA%\peta\Cache`` on Windows).

These are root options, so they come before the command — ``peta --offline
info requests``. They also work with the package shorthand, as in ``peta
--offline requests``.

JSON output records where every source's data came from in each source
record's ``freshness`` field. See :doc:`output-contract`.

Concurrent lookups
-------------------

Requests that do not depend on each other are made at the same time: a
package's vulnerability, download-count and dependent-count lookups query
unrelated services, and ``compare`` resolves both of its packages together.
Measured against the live services, that takes roughly a quarter off ``info``
and a little under half off ``compare``.

The number of requests in flight is bounded by the shared client's connection
limit, so a wider fan-out cannot open connections without limit. Output does
not depend on completion order: results are always assembled in the order they
were asked for, so a comparison renders the same way round every time, and two
sources disagreeing about the same field are still resolved by which was
consulted first.

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

Release artifacts
------------------

``peta artifacts <package>`` answers what a release actually ships before you
depend on it: which wheels and source distributions exist, how large they are,
their SHA-256 digests and upload times, whether any of them is installable on
your target, whether any are yanked, and what publication evidence PyPI
exposes. Without a version it inspects the newest release, preferring a final
version over a prerelease; ``name==version`` inspects that release instead.

Compatibility is evaluated with packaging's own tag and specifier rules — the
same ones an installer applies — not by matching substrings in filenames. A
wheel fits when one of its platform tags is one the target accepts; anything
that is not a wheel is decided by ``Requires-Python`` alone, which says a
source distribution may be *built*, not that building it will succeed.
``--python 3.12`` evaluates against that interpreter version on this machine's
platform, so the question answered is "can I install this here under that
Python". Naming the version you are already running gives the same verdicts as
omitting the flag; naming a different one evaluates that interpreter's tags,
which is the point of the flag.

A verdict of ``unknown`` is deliberately distinct from ``no``: it means peta
could not read the evidence — an unparsable ``Requires-Python``, say — not
that the file was ruled out. peta reports "no file is compatible" only when
every file was actually ruled out, never when it simply could not tell.

A ``name==version`` that the index does not list exits ``1`` like any other
missing target, reported as a missing *release* rather than a missing package,
since the project can exist while that release does not. A version that *is* listed but ships no files is a real
release with an empty file list, and exits ``0``.

.. list-table::
   :header-rows: 1

   * - Flag
     - Effect
   * - ``--python <x.y>``
     - Judge compatibility against this Python version instead of the running
       interpreter.
   * - ``--files``
     - List every distribution file, not just the summary. The Rich view
       shortens digests to a recognizable prefix; ``--format text`` and JSON
       carry them in full.
   * - ``--provenance``
     - Also fetch each file's `PEP 740 <https://peps.python.org/pep-0740/>`_
       provenance document for its Trusted Publisher identity. Off by default
       because it costs one extra request per file that has one.

peta reports publication evidence; it does not verify it. A file with no
provenance has not failed verification, and a Trusted Publisher identity is
reported as PyPI supplied it, not as a checked cryptographic claim. A
provenance lookup that fails is reported as a failure rather than silently
read as an absence, and never fails the command.

Resolution
----------

For ``info``, ``deps``, and ``compare``, ``peta`` checks the local
environment first and falls back to PyPI. Force a source with
``--local``/``-l`` or ``--remote``/``-r``. A ``name==version`` argument is
supported by ``info`` only and always queries PyPI (it cannot be combined
with ``--local``). ``files`` is local-only; ``versions`` and ``artifacts`` are
PyPI-only.
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
     - Package not found, or ``deps --why`` found no path to the target.
   * - ``2``
     - Network or PyPI HTTP error; a lookup that ``--offline`` could not answer
       from the cache; or invalid arguments (an unparsable ``name==version``,
       ``--local`` with a version specifier, ``--json`` combined with a
       non-JSON ``--format``, ``--offline`` combined with ``--refresh``, or a
       parser rejection such as an unknown option or out-of-range
       ``--depth``).

Failures from optional OSV, pypistats, and Libraries.io enrichment sources are
reported as warnings and retain exit code ``0``.

With JSON output, fatal errors use the same versioned envelope as successful
results and appear in the ``errors`` array. The exit codes above are unchanged,
so scripts should inspect both the process status and the envelope.
