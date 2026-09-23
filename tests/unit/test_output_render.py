"""Hardening guarantees that every human-facing output format must keep.

:mod:`peta.cli.output.render` is the one place that knows all the formats, so
it is the one place a test can insist that none of them hands attacker-chosen
bytes to a terminal. A new format added to the dispatch without hardening
fails here rather than in somebody's shell.
"""

from __future__ import annotations

import json

import pytest

from peta.cli.output.render import render_info
from peta.cli.output.selection import OutputFormat
from peta.core.models import PackageInfo

pytestmark = pytest.mark.unit

ESCAPE = "\x1b[31m"
OSC_HYPERLINK = "\x1b]8;;https://attacker.invalid\x07"
HUMAN_FORMATS = [OutputFormat.RICH, OutputFormat.TEXT, OutputFormat.MARKDOWN]


def _hostile() -> PackageInfo:
    """Build a package whose every free-text field is attacker-chosen.

    Returns:
        A package carrying escape sequences and a credentialed URL.
    """
    poison = f"safe{ESCAPE}{OSC_HYPERLINK}click{ESCAPE} [bold]markup[/bold]"
    return PackageInfo(
        name="requests",
        version="1.0",
        source="remote",
        summary=poison,
        author=poison,
        maintainer=poison,
        license=poison,
        homepage="https://example.invalid/?key=install",
        project_urls={"Repo": "https://example.invalid/r"},
        dependencies=[poison],
    )


@pytest.mark.parametrize("output_format", HUMAN_FORMATS)
@pytest.mark.parametrize("color", [True, False])
def test_no_human_format_emits_untrusted_escape_sequences(
    output_format: OutputFormat, *, color: bool
) -> None:
    out = render_info(output_format, _hostile(), arguments={}, color=color)

    assert ESCAPE not in out
    assert "\x1b]8;;" not in out


@pytest.mark.parametrize("output_format", [*HUMAN_FORMATS, OutputFormat.JSON])
def test_every_format_reports_a_declared_url_as_declared(
    output_format: OutputFormat,
) -> None:
    # Redaction belongs where a diagnostic is built, not over rendered output:
    # ``key`` and ``token`` are ordinary query parameters in the wild, and
    # rewriting them here would corrupt the metadata peta exists to report.
    out = render_info(output_format, _hostile(), arguments={}, color=False)

    assert "key=install" in out


def test_json_stays_faithful_to_the_bytes_it_was_given() -> None:
    # Machine output is not a terminal, and a consumer that re-prints it owns
    # that decision. Escaping is json's own ``\\u001b``, so the file is still
    # safe to ``cat`` while the parsed value is unchanged.
    out = render_info(OutputFormat.JSON, _hostile(), arguments={}, color=False)

    assert ESCAPE not in out
    assert ESCAPE in json.loads(out)["result"]["summary"]
