"""CLI application for the project."""
# mypy: disable-error-code="misc"

from __future__ import annotations

import platform
from importlib.metadata import Distribution, PackageNotFoundError

import typer

from peta.__metadata__ import PROJECT_NAME
from peta.core.logging_setup import logger

app = typer.Typer(name="peta", no_args_is_help=True)


@app.command(name="version")
def show_version() -> None:
    """Show the current version number of peta.

    Show the version number:
        peta version

    Example output:
        0.1.0

    Raises:
        typer.Exit: If the package metadata cannot be found.
    """
    try:
        distribution = Distribution.from_name(PROJECT_NAME)
    except PackageNotFoundError:
        logger.error("Package metadata not found for %s", PROJECT_NAME)
        typer.echo(
            f"Error: Package '{PROJECT_NAME}' metadata not found. Is the package installed correctly?",  # noqa: E501
            err=True,
        )
        raise typer.Exit(code=1) from None
    logger.info("Command `version` called.")
    typer.echo(distribution.version)
    logger.info("Version displayed successfully.")


@app.command()
def info() -> None:
    """Display information about the peta application.

    Show application information:
        peta info

    Example output:
        Application Version: 0.1.0
        Python Version: 3.12.0 (CPython)
        Platform: Darwin

    Raises:
        typer.Exit: If the package metadata cannot be found.
    """
    try:
        distribution = Distribution.from_name(PROJECT_NAME)
    except PackageNotFoundError:
        logger.error("Package metadata not found for %s", PROJECT_NAME)
        typer.echo(
            f"Error: Package '{PROJECT_NAME}' metadata not found. Is the package installed correctly?",  # noqa: E501
            err=True,
        )
        raise typer.Exit(code=1) from None
    logger.info("Command `info` called.")
    python_version = platform.python_version()
    python_implementation = platform.python_implementation()
    typer.echo(f"Application Version: {distribution.version}")
    typer.echo(f"Python Version: {python_version} ({python_implementation})")
    typer.echo(f"Platform: {platform.system()}")
    logger.info("Application information displayed successfully.")


@app.command()
def interactive() -> None:  # pragma: no cover
    """Start interactive mode for peta.

    Show application information:
        peta interactive
    """
    from peta.tui.app import main  # noqa: PLC0415

    _ = main()
