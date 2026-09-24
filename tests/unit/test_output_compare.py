"""Tests for the semantic-diff section of ``compare`` in every output format."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

from peta.cli.output import markdown, tables, text
from peta.cli.output.json import format_compare
from peta.core.artifacts import ArtifactFile, Compatibility, ReleaseArtifacts, Target
from peta.core.diff import ReleaseEvidence, diff_packages
from peta.core.models import (
    VULNERABILITY_FIELD,
    EnrichmentFailure,
    PackageInfo,
    Vulnerability,
)
from peta.core.output import SCHEMA_VERSION

if TYPE_CHECKING:
    from peta.core.changes import ChangeSet

GENERATED_AT = "2026-09-04T12:00:00Z"


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="django",
        version="5.2",
        source="remote",
        python_requires=">=3.10",
        dependencies=["asgiref>=3.8.1", "sqlparse>=0.3.1"],
    )
    return replace(base, **over)


def _upgrade() -> tuple[PackageInfo, PackageInfo]:
    return _pkg(), _pkg(
        version="6.0",
        python_requires=">=3.12",
        dependencies=["asgiref>=3.9.1", "tzdata; sys_platform == 'win32'"],
        vulnerabilities=[Vulnerability("PYSEC-9", [], "Bad thing", ["6.0.1"])],
    )


class TestText:
    def test_side_by_side_is_kept_and_followed_by_changes(self) -> None:
        a, b = _upgrade()
        output = text.format_compare(a, b)
        assert output.startswith("Field\tdjango\tdjango")
        assert "Changes:" in output
        assert "  ~ version: 5.2 -> 6.0" in output

    def test_changes_only(self) -> None:
        a, b = _upgrade()
        output = text.format_compare(a, b, changes_only=True)
        assert output.splitlines() == [
            "django 5.2 -> django 6.0",
            "Changes:",
            "Release:",
            "  ~ version: 5.2 -> 6.0",
            "Python:",
            "  ~ requires_python: >=3.10 -> >=3.12",
            "Dependencies:",
            "  ~ asgiref specifier: >=3.8.1 -> >=3.9.1",
            "  - sqlparse: sqlparse>=0.3.1",
            '  + tzdata: tzdata; sys_platform == "win32"',
            "Vulnerabilities:",
            "  + PYSEC-9: Bad thing (fixed in 6.0.1)",
        ]

    def test_no_changes(self) -> None:
        output = text.format_compare(_pkg(), _pkg(), changes_only=True)
        assert output.splitlines()[1:] == ["Changes: none"]

    def test_unknown_group_is_shown(self) -> None:
        failed = _pkg(
            enrichment_failures=[EnrichmentFailure("osv", "down", VULNERABILITY_FIELD)]
        )
        output = text.format_compare(_pkg(), failed, changes_only=True)
        assert "Vulnerabilities:" in output
        assert "  ? unknown: advisory lookup failed for django" in output

    def test_untrusted_values_cannot_add_lines(self) -> None:
        b = _pkg(dependencies=["asgiref>=3.8.1", "evil\n~ forged: line"])
        output = text.format_compare(_pkg(), b, changes_only=True)
        assert "\n~ forged" not in output


class TestMarkdown:
    def test_side_by_side_is_kept_and_followed_by_changes(self) -> None:
        a, b = _upgrade()
        output = markdown.format_compare(a, b)
        assert output.startswith("# Package comparison")
        assert "## Changes" in output
        assert "### Dependencies" in output
        assert "- \\~ `asgiref specifier`: >=3.8.1 → >=3.9.1" in output

    def test_symbols_cannot_start_a_nested_list(self) -> None:
        """``- - x`` and ``- + x`` would render as nested bullets, hiding the sign."""
        a, b = _upgrade()
        output = markdown.format_compare(a, b, changes_only=True)
        assert "- \\- `sqlparse`: sqlparse>=0.3.1" in output
        assert '- \\+ `tzdata`: tzdata; sys_platform == "win32"' in output
        assert "\n- - " not in output
        assert "\n- + " not in output

    def test_changes_only_omits_the_table(self) -> None:
        a, b = _upgrade()
        output = markdown.format_compare(a, b, changes_only=True)
        assert output.startswith("# django 5.2 → django 6.0")
        assert "| Field |" not in output
        assert "### Python" in output

    def test_no_changes(self) -> None:
        output = markdown.format_compare(_pkg(), _pkg(), changes_only=True)
        assert output.endswith("No semantic changes.")

    def test_untrusted_detail_is_inert(self) -> None:
        b = _pkg(summary="x", python_requires="![x](https://evil.example/)")
        output = markdown.format_compare(_pkg(), b, changes_only=True)
        assert "![x](" not in output


class TestRich:
    def test_side_by_side_is_kept_and_followed_by_changes(self) -> None:
        a, b = _upgrade()
        output = tables.render_compare(a, b, color=False)
        assert "django vs django" in output
        assert "Changes:" in output
        assert "    - sqlparse: sqlparse>=0.3.1" in output

    def test_changes_only_omits_the_table(self) -> None:
        a, b = _upgrade()
        output = tables.render_compare(a, b, color=False, changes_only=True)
        assert output.startswith("django 5.2 → django 6.0")
        assert "Field" not in output
        assert "  Python" in output


def _release(version: str, filename: str, sha256: str | None = None) -> ReleaseEvidence:
    file = ArtifactFile(
        filename=filename,
        url=f"https://files.example/{filename}",
        kind="sdist",
        compatibility=Compatibility(compatible=True),
        upload_time=f"2026-0{version[0]}-01T00:00:00Z",
        sha256=sha256,
    )
    return ReleaseEvidence(
        release=ReleaseArtifacts("django", version, Target(), [file])
    )


def _expected_upgrade() -> tuple[PackageInfo, PackageInfo, ChangeSet]:
    """Two releases whose only artifact difference is the expected new digest."""
    a, b = _pkg(), _pkg(version="6.0")
    a_side = _release("5.2", "django-5.2.tar.gz", sha256="a" * 64)
    b_side = _release("6.0", "django-6.0.tar.gz", sha256="b" * 64)
    return a, b, diff_packages(a, b, a_release=a_side, b_release=b_side)


class TestExpectedDifferences:
    def test_text_summarizes_instead_of_listing(self) -> None:
        a, b, diff = _expected_upgrade()
        output = text.format_compare(a, b, diff, changes_only=True)
        assert "artifact_hash" not in output
        assert "sdist sha256" not in output
        assert (
            "  · 1 expected difference not listed "
            "(different files carry different digests and sizes)"
        ) in output

    def test_markdown_and_rich_summarize_too(self) -> None:
        a, b, diff = _expected_upgrade()
        md = markdown.format_compare(a, b, diff, changes_only=True)
        rich = tables.render_compare(a, b, diff, color=False, changes_only=True)
        assert "- _1 expected difference not listed" in md
        assert "    · 1 expected difference not listed" in rich

    def test_json_keeps_the_record_and_flags_it(self) -> None:
        a, b, diff = _expected_upgrade()
        data = json.loads(format_compare(a, b, diff=diff, generated_at=GENERATED_AT))
        hashes = [
            c
            for c in data["result"]["diff"]["changes"]
            if c["kind"] == "artifact_hash_changed"
        ]
        assert hashes == [
            {
                "group": "artifacts",
                "kind": "artifact_hash_changed",
                "subject": "sdist .tar.gz",
                "before": "a" * 64,
                "after": "b" * 64,
                "expected": True,
            }
        ]


class TestJson:
    def test_releases_alone_still_diff_the_artifacts(self) -> None:
        """Without an explicit diff, the one computed must use the listings."""
        releases = (
            _release("5.2", "django-5.2.tar.gz"),
            _release("6.0", "django-6.0.tar.gz"),
        )
        data = json.loads(
            format_compare(
                _pkg(),
                _pkg(version="6.0"),
                releases=releases,
                generated_at=GENERATED_AT,
            )
        )
        kinds = {change["kind"] for change in data["result"]["diff"]["changes"]}
        assert "release_date_changed" in kinds

    def test_changes_have_stable_kinds_and_values(self) -> None:
        a, b = _upgrade()
        data = json.loads(format_compare(a, b, generated_at=GENERATED_AT))
        assert data["schema_version"] == SCHEMA_VERSION
        assert len(data["result"]["packages"]) == 2
        changes = data["result"]["diff"]["changes"]
        assert changes[0] == {
            "group": "release",
            "kind": "version_changed",
            "subject": "version",
            "before": "5.2",
            "after": "6.0",
            "expected": False,
        }
        assert {change["kind"] for change in changes} == {
            "version_changed",
            "python_requires_changed",
            "dependency_specifier_changed",
            "dependency_removed",
            "dependency_added",
            "vulnerability_added",
        }
        assert data["result"]["diff"]["unknown"] == []

    def test_unknown_groups_are_listed(self) -> None:
        failed = _pkg(
            enrichment_failures=[EnrichmentFailure("osv", "down", VULNERABILITY_FIELD)]
        )
        data = json.loads(format_compare(_pkg(), failed, generated_at=GENERATED_AT))
        assert data["result"]["diff"]["unknown"] == [
            {"group": "vulnerabilities", "reason": "advisory lookup failed for django"}
        ]

    def test_release_listings_are_recorded_as_sources(self) -> None:
        a, b = _pkg(), _pkg(version="6.0")
        releases = (
            _release("5.2", "django-5.2.tar.gz"),
            _release("6.0", "django-6.0.tar.gz"),
        )
        diff = diff_packages(a, b, a_release=releases[0], b_release=releases[1])
        data = json.loads(
            format_compare(
                a, b, diff=diff, releases=releases, generated_at=GENERATED_AT
            )
        )
        assert data["status"] == "success"
        listing = [s for s in data["sources"] if s["fields"] == ["result.diff"]]
        assert [(s["name"], s["state"], s["target"]) for s in listing] == [
            ("pypi", "success", "django 5.2"),
            ("pypi", "success", "django 6.0"),
        ]
        kinds = [change["kind"] for change in data["result"]["diff"]["changes"]]
        assert "release_date_changed" in kinds

    def test_failed_listing_makes_the_envelope_partial(self) -> None:
        a, b = _pkg(), _pkg(version="6.0")
        releases = (
            _release("5.2", "django-5.2.tar.gz"),
            ReleaseEvidence(reason="django 6.0: network down"),
        )
        diff = diff_packages(a, b, a_release=releases[0], b_release=releases[1])
        data = json.loads(
            format_compare(
                a, b, diff=diff, releases=releases, generated_at=GENERATED_AT
            )
        )
        assert data["status"] == "partial"
        assert data["warnings"] == [
            {
                "code": "enrichment_failed",
                "message": "django 6.0: network down",
                "source": "pypi",
            }
        ]
        failed = [s for s in data["sources"] if s["state"] == "failed"]
        assert failed[0]["reason"] == "django 6.0: network down"
        assert {e["group"] for e in data["result"]["diff"]["unknown"]} == {
            "artifacts",
            "provenance",
        }
