Installation
============

<<<<<<< before updating
``peta`` is an end-user command-line tool. Install it into an isolated
environment with your preferred tool manager.

Requirements
------------
=======
``peta`` is an end-user application, not a library, so install
it as a standalone tool rather than as a project dependency. Its primary entry
point is the ``peta`` command.
>>>>>>> after updating

* Python 3.14 or newer.

<<<<<<< before updating
Using uv
--------
=======
Install ``peta`` into an isolated environment with your
preferred tool installer:

.. code-block:: sh

   uv tool install peta

.. code-block:: sh

   pipx install peta

Or run it without installing:
>>>>>>> after updating

.. code-block:: bash

<<<<<<< before updating
   uvx peta requests        # run without installing
   uv tool install peta     # install as a persistent tool

Using pipx
----------
=======
   uvx peta

Verify release provenance
-------------------------

Public-repository release distributions include Sigstore-signed build
provenance. After downloading a wheel or source distribution, verify that the
release workflow built it from ``main`` in this repository:
>>>>>>> after updating

.. code-block:: bash

<<<<<<< before updating
   pipx install peta
=======
   gh attestation verify <downloaded-distribution> \
     --repo hasansezertasan/peta \
     --signer-workflow hasansezertasan/peta/.github/workflows/release.yml \
     --source-ref refs/heads/main

Artifact attestations are available for public repositories on current GitHub
plans. Private and internal repositories require GitHub Enterprise Cloud and
the repository variable ``ENABLE_PRIVATE_ATTESTATIONS=true``.
>>>>>>> after updating

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

<<<<<<< before updating
   scoop bucket add hasansezertasan https://github.com/hasansezertasan/scoop-bucket
   scoop install peta
=======
   cd peta
   uv tool install .
>>>>>>> after updating
