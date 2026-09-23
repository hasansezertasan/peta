"""Hardening guarantees that every human-facing output format must keep.

:mod:`peta.cli.output.render` is the one place that knows all the formats, so
it is the one place a test can insist that none of them hands attacker-chosen
bytes to a terminal. A new format added to the dispatch without hardening
fails here rather than in somebody's shell.
"""

from __future__ import annotations

import json

import pytest

from peta.cli.output.render import (
    render_artifacts,
    render_files,
    render_info,
    render_target,
    render_why,
)
from peta.cli.output.selection import OutputFormat
from peta.core.artifacts import ArtifactFile, Compatibility, ReleaseArtifacts, Target
from peta.core.local import LocalTarget
from peta.core.models import (
    DependencyNode,
    EnrichmentFailure,
    PackageInfo,
    Vulnerability,
)

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


def test_the_target_banner_cannot_emit_escape_sequences() -> None:
    # Printed above human output rather than through a formatter, and built
    # from paths — ``--path`` and the target interpreter's own ``sys.path`` —
    # whose directory names can carry escape sequences.
    target = LocalTarget(
        paths=(f"/srv/evil{OSC_HYPERLINK}dir{ESCAPE}",),
        interpreter=f"/opt/py{ESCAPE}thon",
        marker_environment={
            "platform_python_implementation": "CPython",
            "python_full_version": "3.14.0",
            "sys_platform": "linux",
        },
    )

    banner = render_target(OutputFormat.TEXT, target)

    assert "\x1b" not in banner
    assert "/srv/evil" in banner


def test_the_target_banner_stays_on_one_line() -> None:
    # sanitize_terminal keeps newlines for the multi-line formatters, so the
    # banner escapes its own: a directory named with a line break would
    # otherwise forge lines of output.
    target = LocalTarget(
        paths=("/srv/ok\nTarget environment: trusted\r",),
        interpreter=None,
        marker_environment={
            "platform_python_implementation": "CPython",
            "python_full_version": "3.14.0",
            "sys_platform": "linux",
        },
    )

    banner = render_target(OutputFormat.TEXT, target)

    assert "\n" not in banner
    assert "\r" not in banner
    assert r"/srv/ok\nTarget environment: trusted\r" in banner


HOSTILE_LINE = f"ok{ESCAPE}{OSC_HYPERLINK}\n  forged line"
"""A value that tries both terminal controls and a line of its own."""


def _assert_inert(out: str) -> None:
    assert ESCAPE not in out
    assert "\x1b]8;;" not in out
    assert "\n  forged line" not in out


class TestBlocksAppendedAfterRichRendering:
    """Plain text that Rich never sees must be hardened on its own.

    The Rich formatters add blocks after ``console.render`` has run — the
    vulnerability and enrichment blocks, artifact details and notes — and
    ``files`` and ``why`` never render through Rich at all, so the segment
    hardening inside ``render`` does not reach any of them.
    """

    @pytest.mark.parametrize("color", [True, False])
    def test_vulnerability_and_enrichment_blocks(self, *, color: bool) -> None:
        package = PackageInfo(
            name="requests",
            version="1.0",
            source="remote",
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-1", aliases=[], summary=HOSTILE_LINE, fixed_in=["2.0"]
                )
            ],
            enrichment_failures=[
                EnrichmentFailure(source="osv", reason=HOSTILE_LINE, field=None)
            ],
        )

        out = render_info(OutputFormat.RICH, package, arguments={}, color=color)

        _assert_inert(out)
        assert "forged line" in out

    def test_peta_keeps_its_own_color_alongside_them(self) -> None:
        package = PackageInfo(
            name="requests",
            version="1.0",
            source="remote",
            enrichment_failures=[
                EnrichmentFailure(source="osv", reason=HOSTILE_LINE, field=None)
            ],
        )

        assert "\x1b[" in render_info(
            OutputFormat.RICH, package, arguments={}, color=True
        )

    @pytest.mark.parametrize("detailed", [True, False])
    def test_artifact_details_and_notes(self, *, detailed: bool) -> None:
        wheel = ArtifactFile(
            filename=f"pkg{ESCAPE}-1.0.whl",
            url="https://files.invalid/pkg-1.0.whl",
            kind="wheel",
            compatibility=Compatibility(compatible=True),
            yanked=True,
            yanked_reason=HOSTILE_LINE,
        )
        release = ReleaseArtifacts(
            name="pkg", version="1.0", target=Target("3.13"), files=[wheel]
        )

        out = render_artifacts(
            OutputFormat.RICH,
            release,
            arguments={},
            color=True,
            detailed=detailed,
            retrieved_at="2026-01-01T00:00:00Z",
        )

        _assert_inert(out)

    def test_file_listing(self) -> None:
        package = PackageInfo(
            name="requests", version="1.0", source="local", files=[HOSTILE_LINE]
        )

        _assert_inert(
            render_files(OutputFormat.RICH, package, arguments={}, color=True)
        )

    def test_dependency_paths(self) -> None:
        out = render_why(
            OutputFormat.RICH,
            "requests",
            [["app", HOSTILE_LINE, "requests"]],
            DependencyNode("app", ""),
            arguments={},
            color=True,
        )

        _assert_inert(out)


def test_the_target_banner_is_inert_markdown_above_a_markdown_document() -> None:
    # Prepended to the document by the CLI rather than built by the Markdown
    # formatter, so it needs that formatter's escaping explicitly: a --path
    # directory named like an image would otherwise load a remote URL.
    target = LocalTarget(
        paths=("/srv/![x](https://attacker.invalid/t)",),
        interpreter=None,
        marker_environment={
            "platform_python_implementation": "CPython",
            "python_full_version": "3.14.0",
            "sys_platform": "linux",
        },
    )

    banner = render_target(OutputFormat.MARKDOWN, target)

    assert "![x](" not in banner
    assert r"!\[x\](https://attacker.invalid/t)" in banner
