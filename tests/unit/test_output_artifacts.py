"""Unit tests for the four artifact renderers."""

import json as jsonlib
from dataclasses import replace
from typing import cast

import pytest

from peta.cli.output import json as json_output, markdown, tables, text
from peta.core.artifacts import (
    ArtifactFile,
    Compatibility,
    Publisher,
    PublisherFailure,
    ReleaseArtifacts,
    Target,
)
from peta.core.cache import Provenance

pytestmark = pytest.mark.unit

GENERATED_AT = "2026-09-04T12:00:00Z"
_RETRIEVAL = Provenance("live", "2026-09-04T11:59:00Z")


def _wheel(**over: object) -> ArtifactFile:
    base = ArtifactFile(
        filename="pkg-1.0-py3-none-any.whl",
        url="https://files.invalid/pkg-1.0-py3-none-any.whl",
        kind="wheel",
        compatibility=Compatibility(compatible=True),
        size=1024,
        upload_time="2026-01-02T03:04:05Z",
        sha256="a" * 64,
        requires_python=">=3.8",
        core_metadata=True,
        tags=("py3-none-any",),
    )
    return replace(base, **over)


def _sdist(**over: object) -> ArtifactFile:
    base = ArtifactFile(
        filename="pkg-1.0.tar.gz",
        url="https://files.invalid/pkg-1.0.tar.gz",
        kind="sdist",
        compatibility=Compatibility(compatible=True),
        size=2048,
        upload_time="2026-01-02T03:04:05Z",
        sha256="b" * 64,
        requires_python=">=3.8",
    )
    return replace(base, **over)


def _release(*files: ArtifactFile, **over: object) -> ReleaseArtifacts:
    base = ReleaseArtifacts(
        name="pkg",
        version="1.0",
        target=Target("3.13"),
        files=list(files) or [_wheel(), _sdist()],
    )
    return replace(base, **over)


class TestRich:
    def test_summary_answers_the_headline_questions(self) -> None:
        out = tables.render_artifacts(_release(), color=False)
        assert "pkg 1.0" in out
        assert "Compatible (Python 3.13)" in out
        assert "2 of 2" in out
        assert "3.1 kB" in out

    def test_detail_lists_every_file(self) -> None:
        out = tables.render_artifacts(_release(), color=False, detailed=True)
        assert "pkg-1.0-py3-none-any.whl" in out
        assert "pkg-1.0.tar.gz" in out
        assert "sha256:aaaaaaaaaaaa…" in out
        assert "metadata" in out

    def test_a_release_with_no_files_says_so(self) -> None:
        out = tables.render_artifacts(_release(*[], files=[]), color=False)
        assert out == "No distribution files published for pkg 1.0."

    def test_notes_explain_yanks_and_total_incompatibility(self) -> None:
        release = _release(
            _wheel(
                compatibility=Compatibility(compatible=False, reason="no tag matches"),
                yanked=True,
                yanked_reason="bad build",
            )
        )
        out = tables.render_artifacts(release, color=False)
        assert "No file is compatible with Python 3.13" in out
        assert "no tag matches" in out
        assert "Yanked: pkg-1.0-py3-none-any.whl (bad build)" in out

    def test_unknown_verdicts_are_never_reported_as_incompatible(self) -> None:
        # "unknown" means peta could not read the evidence. Announcing that
        # nothing is compatible would assert a verdict it never reached.
        release = _release(
            _wheel(compatibility=Compatibility(compatible=None, reason="unreadable"))
        )
        out = tables.render_artifacts(release, color=False)
        assert "No file is compatible" not in out

    def test_a_publisher_identity_is_visible_in_the_default_format(self) -> None:
        release = _release(
            _wheel(
                provenance_url="https://pypi.org/integrity/x/provenance",
                publishers=(Publisher(kind="GitHub", claims={"repository": "a/b"}),),
            )
        )
        summary = tables.render_artifacts(release, color=False)
        assert "GitHub repository=a/b" in summary
        detail = tables.render_artifacts(release, color=False, detailed=True)
        assert "published by GitHub repository=a/b" in detail

    def test_a_yank_without_a_reason_still_reports_the_yank(self) -> None:
        out = tables.render_artifacts(_release(_wheel(yanked=True)), color=False)
        assert "no reason given" in out

    def test_a_failed_provenance_lookup_is_visible(self) -> None:
        release = _release(
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),)
        )
        assert "Provenance lookup failed" in tables.render_artifacts(
            release, color=False
        )

    def test_missing_digest_size_and_upload_time_render_as_gaps(self) -> None:
        release = _release(_wheel(sha256=None, size=None, upload_time=None))
        out = tables.render_artifacts(release, color=False, detailed=True)
        assert "no digest" in out
        assert "unknown" in out

    def test_an_unknown_verdict_carries_its_reason(self) -> None:
        release = _release(
            _wheel(compatibility=Compatibility(compatible=None, reason="unreadable"))
        )
        out = tables.render_artifacts(release, color=False, detailed=True)
        assert "compatible: unknown (unreadable)" in out

    def test_a_file_with_no_flags_renders_a_dash(self) -> None:
        release = _release(_sdist(core_metadata=False))
        out = tables.render_artifacts(release, color=False, detailed=True)
        assert " · -" in out


class TestSummaryRows:
    def test_unknown_verdicts_are_counted_not_hidden(self) -> None:
        # "0 of 1" alone reads as a ruled-out file.
        release = _release(
            _wheel(compatibility=Compatibility(compatible=None, reason="unreadable"))
        )
        assert "0 of 1 (1 unknown)" in tables.render_artifacts(release, color=False)

    def test_an_aggregate_over_unsized_files_is_not_presented_as_exact(self) -> None:
        release = _release(_wheel(size=1024), _sdist(size=None))
        assert "at least 1.0 kB" in tables.render_artifacts(release, color=False)

    def test_a_partly_yanked_release_is_not_reported_as_unyanked(self) -> None:
        release = _release(_wheel(yanked=True), _sdist())
        out = tables.render_artifacts(release, color=False)
        assert "1 of 2 files" in out

    def test_a_fully_yanked_release_still_says_so(self) -> None:
        release = _release(_wheel(yanked=True), _sdist(yanked=True))
        assert "entire release" in tables.render_artifacts(release, color=False)


class TestText:
    def test_summary_and_full_digests(self) -> None:
        out = text.format_artifacts(_release(), detailed=True)
        assert "Artifacts for pkg 1.0" in out
        assert "Requires-Python: >=3.8" in out
        assert "a" * 64 in out

    def test_notes_name_the_affected_file(self) -> None:
        release = _release(
            _wheel(
                compatibility=Compatibility(compatible=None, reason="unreadable"),
                yanked=True,
            ),
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),),
        )
        out = text.format_artifacts(release, detailed=True)
        assert "unknown" in out
        assert "- pkg-1.0-py3-none-any.whl: unreadable" in out
        assert "yanked: no reason given" in out
        assert "provenance lookup failed" in out

    def test_an_empty_release_still_summarizes(self) -> None:
        out = text.format_artifacts(_release(files=[]), detailed=True)
        assert "Files: 0" in out
        assert "Requires-Python: -" in out


class TestMarkdown:
    def test_summary_and_file_tables(self) -> None:
        out = markdown.format_artifacts(_release(), detailed=True)
        assert out.startswith("# Artifacts for pkg 1.0")
        assert "| Field | Value |" in out
        assert "`pkg-1.0-py3-none-any.whl`" in out

    def test_notes_section(self) -> None:
        release = _release(
            _wheel(
                compatibility=Compatibility(compatible=False, reason="no tag matches"),
                yanked=True,
                yanked_reason="bad build",
                sha256=None,
            ),
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),),
        )
        out = markdown.format_artifacts(release, detailed=True)
        assert "## Notes" in out
        assert "**yanked:** bad build" in out
        assert "**provenance lookup failed:**" in out

    def test_no_notes_section_when_nothing_is_wrong(self) -> None:
        assert "## Notes" not in markdown.format_artifacts(_release())


class TestJson:
    def _envelope(
        self, release: ReleaseArtifacts, *, publishers: bool = False
    ) -> dict[str, object]:
        raw = json_output.format_artifacts(
            release, generated_at=GENERATED_AT, publishers=publishers
        )
        return cast("dict[str, object]", jsonlib.loads(raw))

    def test_files_and_provenance_are_structured(self) -> None:
        release = _release(
            _wheel(
                provenance_url="https://pypi.org/integrity/x/provenance",
                publishers=(
                    Publisher(
                        kind="GitHub", claims={"repository": "a/b", "workflow": "p.yml"}
                    ),
                ),
            )
        )
        data = self._envelope(release, publishers=True)
        result = cast("dict[str, object]", data["result"])
        files = cast("list[dict[str, object]]", result["files"])
        provenance = cast("dict[str, object]", files[0]["provenance"])
        assert provenance["available"] is True
        publishers = cast("list[dict[str, object]]", provenance["publishers"])
        assert publishers[0]["kind"] == "GitHub"
        assert publishers[0]["claims"] == {"repository": "a/b", "workflow": "p.yml"}
        assert files[0]["tags"] == ["py3-none-any"]
        assert files[0]["compatible"] is True
        assert result["summary"] == {
            "files": 1,
            "wheels": 1,
            "sdists": 0,
            "compatible": 1,
            "total_size": 1024,
            "unsized_files": 0,
            "yanked": False,
            "with_provenance": 1,
        }

    def test_unknown_compatibility_is_null_not_false(self) -> None:
        release = _release(
            _wheel(compatibility=Compatibility(compatible=None, reason="unreadable"))
        )
        data = self._envelope(release)
        files = cast(
            "list[dict[str, object]]",
            cast("dict[str, object]", data["result"])["files"],
        )
        assert files[0]["compatible"] is None
        assert files[0]["incompatibility"] == "unreadable"

    def test_sources_attribute_publishers_field_by_field(self) -> None:
        release = _release(
            _wheel(publishers=(Publisher(kind="GitHub"),)),
            _sdist(),
            publisher_lookups=("pkg-1.0-py3-none-any.whl",),
            publisher_retrieval=_RETRIEVAL,
        )
        data = self._envelope(release, publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        provenance = next(s for s in sources if s["name"] == "pypi-provenance")
        assert provenance["state"] == "success"
        assert provenance["fields"] == ["result.files[0].provenance.publishers"]

    def test_a_release_with_no_provenance_is_skipped_not_timestamped(self) -> None:
        # Nothing was requested, so claiming the source answered at the
        # envelope'"'"'s own generation time would be an invented retrieval.
        data = self._envelope(_release(), publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        provenance = next(s for s in sources if s["name"] == "pypi-provenance")
        assert provenance["state"] == "skipped"
        assert provenance["reason"] == "no file exposes provenance"
        assert "retrieved_at" not in provenance
        assert "freshness" not in provenance

    def test_a_reached_release_with_no_publishers_is_empty(self) -> None:
        release = _release(
            _wheel(),
            publisher_lookups=("pkg-1.0-py3-none-any.whl",),
            publisher_retrieval=_RETRIEVAL,
        )
        data = self._envelope(release, publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        provenance = next(s for s in sources if s["name"] == "pypi-provenance")
        assert provenance["state"] == "empty"
        assert provenance["retrieved_at"] == "2026-09-04T11:59:00Z"

    def test_a_mixed_lookup_attributes_both_outcomes_to_real_paths(self) -> None:
        # One state cannot describe both outcomes, and a consumer must be able
        # to tell the path PyPI supplied nothing for from the path peta could
        # not reach — without parsing a filename back out of a warning.
        release = _release(
            _wheel(publishers=(Publisher(kind="GitHub"),)),
            _sdist(),
            publisher_lookups=("pkg-1.0-py3-none-any.whl",),
            publisher_retrieval=_RETRIEVAL,
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),),
        )
        data = self._envelope(release, publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        records = [s for s in sources if s["name"] == "pypi-provenance"]
        assert [(r["state"], r["fields"]) for r in records] == [
            ("success", ["result.files[0].provenance.publishers"]),
            ("failed", ["result.files[1].provenance.publishers"]),
        ]
        assert records[1]["reason"] == "pkg-1.0.tar.gz: HTTP 503"
        assert "retrieved_at" not in records[1]

    def test_a_reached_file_survives_a_sibling_failure(self) -> None:
        # The wheel was asked about and genuinely has no publisher. That is
        # evidence, and it must not vanish because the sdist's request fell
        # over — otherwise it is indistinguishable from never being reached.
        release = _release(
            _wheel(),
            _sdist(),
            publisher_lookups=("pkg-1.0-py3-none-any.whl",),
            publisher_retrieval=_RETRIEVAL,
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),),
        )
        data = self._envelope(release, publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        records = [s for s in sources if s["name"] == "pypi-provenance"]
        assert [(r["state"], r["fields"]) for r in records] == [
            ("empty", ["result.files[0].provenance.publishers"]),
            ("failed", ["result.files[1].provenance.publishers"]),
        ]

    def test_every_failure_reason_reaches_the_source_record(self) -> None:
        release = _release(
            publisher_failures=(
                PublisherFailure("a.whl", "HTTP 503"),
                PublisherFailure("b.whl", "timed out"),
            )
        )
        data = self._envelope(release, publishers=True)
        sources = cast("list[dict[str, object]]", data["sources"])
        failed = next(s for s in sources if s["state"] == "failed")
        assert failed["reason"] == "a.whl: HTTP 503; b.whl: timed out"

    def test_an_incomplete_size_total_is_marked_in_json(self) -> None:
        # The human view says "at least"; machine output needs the same fact.
        data = self._envelope(_release(_wheel(size=1024), _sdist(size=None)))
        summary = cast(
            "dict[str, object]", cast("dict[str, object]", data["result"])["summary"]
        )
        assert summary["total_size"] == 1024
        assert summary["unsized_files"] == 1

    def test_a_failed_publisher_lookup_is_a_partial_envelope(self) -> None:
        release = _release(
            publisher_failures=(PublisherFailure("pkg-1.0.tar.gz", "HTTP 503"),)
        )
        data = self._envelope(release, publishers=True)
        assert data["status"] == "partial"
        sources = cast("list[dict[str, object]]", data["sources"])
        records = [s for s in sources if s["name"] == "pypi-provenance"]
        assert [r["state"] for r in records] == ["failed"]
        assert records[0]["reason"] == "pkg-1.0.tar.gz: HTTP 503"
        assert "retrieved_at" not in records[0]
        warnings = cast("list[dict[str, object]]", data["warnings"])
        assert warnings[0]["code"] == "enrichment_failed"

    def test_a_release_with_no_files_is_empty_not_failed(self) -> None:
        data = self._envelope(_release(files=[]))
        assert data["status"] == "empty"
        sources = cast("list[dict[str, object]]", data["sources"])
        assert sources[0]["state"] == "empty"

    def test_provenance_source_is_omitted_unless_asked_for(self) -> None:
        data = self._envelope(_release())
        sources = cast("list[dict[str, object]]", data["sources"])
        assert [s["name"] for s in sources] == ["pypi"]
        assert sources[0]["fields"] == ["result.files"]
