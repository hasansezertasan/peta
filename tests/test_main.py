"""Tests for the package's runnable entrypoint (``python -m peta``)."""

import importlib


def test_main_is_callable() -> None:
    """The package exposes a callable ``main()`` entrypoint.

    Every standalone-executable build (launcher / freezer / compiler — see
    ADR-007) targets ``peta.__main__:main``, so this pins the
    contract that the symbol exists and is callable for whichever component is
    enabled. Importing the module also executes the top-level ``from ... import``
    for the selected component, so a broken import in the active branch fails
    here. The module is imported (not executed as ``__main__``), so a runnable
    component's blocking ``main()`` (server loop, mainloop, ...) is never invoked.
    """
    main_module = importlib.import_module("peta.__main__")

    assert callable(main_module.main)
    # CLI dispatch wires the Typer ``app`` into __main__; assert it resolved.
    assert hasattr(main_module, "app")
