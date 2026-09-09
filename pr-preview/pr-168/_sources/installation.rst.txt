Installation
============

``peta`` is an end-user command-line tool. Install it into an isolated
environment with your preferred tool manager.

Requirements
------------

* Python 3.14 or newer.

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
