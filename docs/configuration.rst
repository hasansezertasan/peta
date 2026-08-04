Configuration
=============

``peta`` reads its behavior from CLI flags first; environment variables
provide defaults for behavior that has no dedicated flag.

.. list-table::
   :header-rows: 1

   * - Variable
     - Effect
   * - ``NO_COLOR``
     - Any non-empty value disables colored Rich output, the same as passing
       ``--no-color``. The ``--no-color`` flag always takes precedence over
       this variable.
   * - ``LIBRARIES_IO_API_KEY``
     - API key used to look up a package's dependent count from
       `libraries.io <https://libraries.io/>`_. Without it, ``peta info``
       simply omits the dependent count (it degrades to ``None``); no
       request is made. Not required for the download count, which comes
       from `pypistats.org <https://pypistats.org/>`_.
