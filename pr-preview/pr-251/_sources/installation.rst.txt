Installation
============

``peta`` is an end-user command-line tool. Install it into an isolated
environment with your preferred tool manager.

Requirements
------------

* Python 3.11 or newer (3.11, 3.12, 3.13 and 3.14 are tested).

Supported Python versions
^^^^^^^^^^^^^^^^^^^^^^^^^

``peta`` supports the CPython minor releases that are maintained upstream
(see the `Python release status page <https://devguide.python.org/versions/>`_)
and that it tests continuously. Each supported version is declared in four
places that move together:

* ``requires-python`` and the ``Programming Language :: Python :: 3.X``
  classifiers in the published package metadata;
* a tox test env of the same name;
* a row in the CI test matrix, run on Linux, macOS and Windows;
* a ``mypy --python-version`` pass in the style checks.

A test in the suite fails if these disagree, so the floor is never lowered
without CI coverage for it. The floor rises once a version reaches its upstream
end of life. Python 3.10 was left out for that reason: its end of life
(October 2026) came within weeks of ``peta`` first supporting older versions,
so it would have been added only to be dropped again.

The interpreter ``peta`` *runs on* and the environment it *inspects* are
separate. On ``info``, ``compare``, ``deps``, ``files`` and ``origin``, ``--python PATH``
(an interpreter) and ``--path DIR`` (a metadata directory) point an isolated
``peta`` at another environment, and that environment may be older than
``peta``'s own floor. CI points ``--python`` at a real Python 3.8 interpreter
on Linux, macOS and Windows from every supported ``peta`` runtime, and the
small script it runs inside the target is also parsed with Python 3.7's
grammar. ``--path`` reads the metadata older tools wrote, from
``Metadata-Version`` 1.0 to setuptools ``.egg-info`` directories.

Using uv
--------

.. code-block:: bash

   uvx peta requests        # run without installing
   uv tool install peta     # install as a persistent tool

Using pipx
----------

.. code-block:: bash

   pipx install peta

Using pip
---------

.. code-block:: bash

   pip install peta

Using Homebrew
--------------

On macOS/Linux, install ``peta`` from the
`Homebrew tap <https://github.com/hasansezertasan/homebrew-tap>`_:

.. code-block:: bash

   brew install hasansezertasan/tap/peta

Using Scoop
-----------

On Windows, install ``peta`` from the
`Scoop bucket <https://github.com/hasansezertasan/scoop-bucket>`_:

.. code-block:: bash

   scoop bucket add hasansezertasan https://github.com/hasansezertasan/scoop-bucket
   scoop install peta

Verify release provenance
-------------------------

Public-repository release distributions include Sigstore-signed build
provenance. After downloading a wheel or source distribution, verify that the
release workflow built it from ``main`` in this repository:

.. code-block:: bash

   gh attestation verify <downloaded-distribution> \
     --repo hasansezertasan/peta \
     --signer-workflow hasansezertasan/peta/.github/workflows/release.yml \
     --source-ref refs/heads/main
