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
