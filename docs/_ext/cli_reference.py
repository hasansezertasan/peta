"""Sphinx directive that renders command help from peta's Typer application."""

from docutils import nodes
from docutils.parsers.rst import Directive
from typer.testing import CliRunner

from peta.cli.app import app as cli_app


class PetaCliDirective(Directive):
    """Render the root and subcommand help as literal blocks."""

    has_content = False

    def run(self) -> list[nodes.Node]:
        """Build documentation nodes from the live Typer application.

        Returns:
            Sections containing help for the root command and every subcommand.
        """
        runner = CliRunner()
        commands = [
            command.name or command.callback.__name__
            for command in cli_app.registered_commands
            if command.callback is not None
        ]
        sections: list[nodes.Node] = []
        for command in [None, *commands]:
            args = ["--help"] if command is None else [command, "--help"]
            result = runner.invoke(cli_app, args)
            if result.exit_code != 0:
                msg = f"Could not render help for {' '.join(args)}"
                raise self.error(msg) from result.exception
            title = "peta" if command is None else f"peta {command}"
            section = nodes.section(ids=[nodes.make_id(title)])
            section += nodes.title(text=title)
            section += nodes.literal_block(text=result.stdout.rstrip())
            sections.append(section)
        return sections


def setup(app: object) -> dict[str, bool]:
    """Register the directive with Sphinx.

    Returns:
        Extension metadata declaring parallel-build safety.
    """
    app.add_directive("peta-cli", PetaCliDirective)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
