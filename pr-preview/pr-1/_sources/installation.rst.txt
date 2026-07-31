Installation
============

Possible extras:

- ``cli``: Installs typer and adds ``peta`` as a command.
- ``all``: Installs all extras if available.

Stable release
--------------

To install ``peta``, run this command in your terminal:

.. code-block:: sh

   uv add peta

Or if you prefer to use ``pip``:

.. code-block:: sh

   pip install peta

From source
-----------

The source files for ``peta`` can be downloaded from the
`GitHub repo <https://github.com/hasansezertasan/peta>`_.

You can either clone the public repository:

.. code-block:: sh

   git clone https://github.com/hasansezertasan/peta.git

Or download the
`tarball <https://github.com/hasansezertasan/peta/tarball/main>`_:

.. code-block:: sh

   mkdir peta
   curl -fL https://github.com/hasansezertasan/peta/tarball/main | tar -xz --strip-components=1 -C peta

Once you have a copy of the source, you can install it with:

.. code-block:: sh

   cd peta
   uv pip install .
