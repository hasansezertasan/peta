"""Tests for the semantic package diff engine."""

from __future__ import annotations

from dataclasses import replace

import pytest

from peta.core.artifacts import ArtifactFile, Compatibility, ReleaseArtifacts, Target
from peta.core.changes import Change
from peta.core.diff import ReleaseEvidence, diff_packages
from peta.core.models import (
    VULNERABILITY_FIELD,
    EnrichmentFailure,
    PackageInfo,
    Vulnerability,
)


def _pkg(**over: object) -> PackageInfo:
    base = PackageInfo(
        name="django",
        version="5.2",
        source="remote",
        license="BSD-3-Clause",
        license_source="expression",
        python_requires=">=3.10",
        dependencies=["asgiref>=3.8.1", "sqlparse>=0.3.1"],
    )
    return replace(base, **over)


def _kinds(changes: tuple[Change, ...] | list[Change]) -> list[str]:
    return [change.kind for change in changes]


class TestReleaseFields:
    def test_identical_packages_have_no_changes(self) -> None:
        diff = diff_packages(_pkg(), _pkg())
        assert diff.changes == ()
        assert diff.unknown == ()

    def test_same_project_versions(self) -> None:
        diff = diff_packages(_pkg(), _pkg(version="6.0"))
        assert diff.changes == (
            Change("release", "version_changed", "version", "5.2", "6.0"),
        )

    def test_different_projects(self) -> None:
        diff = diff_packages(_pkg(), _pkg(name="flask", version="5.2"))
        assert _kinds(diff.changes) == ["project_changed"]
        assert diff.changes[0].before == "django"
        assert diff.changes[0].after == "flask"

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            pytest.param("Django", "django", id="case"),
            pytest.param("zope.interface", "Zope_Interface", id="separators"),
        ],
    )
    def test_canonicalized_names_are_not_a_change(self, a: str, b: str) -> None:
        assert diff_packages(_pkg(name=a), _pkg(name=b)).changes == ()

    def test_equivalent_versions_are_not_a_change(self) -> None:
        assert diff_packages(_pkg(version="1.0"), _pkg(version="1.0.0")).changes == ()


class TestPython:
    def test_range_change(self) -> None:
        diff = diff_packages(_pkg(), _pkg(python_requires=">=3.12"))
        assert diff.changes == (
            Change(
                "python",
                "python_requires_changed",
                "requires_python",
                ">=3.10",
                ">=3.12",
            ),
        )

    def test_reordered_specifiers_are_not_a_change(self) -> None:
        a = _pkg(python_requires=">=3.10, <4")
        b = _pkg(python_requires="<4,>=3.10.0")
        assert diff_packages(a, b).changes == ()

    def test_missing_on_one_side(self) -> None:
        diff = diff_packages(_pkg(python_requires=None), _pkg())
        assert diff.changes[0].before is None
        assert diff.changes[0].after == ">=3.10"

    def test_unparsable_range_is_compared_as_text(self) -> None:
        diff = diff_packages(_pkg(), _pkg(python_requires="not a range"))
        assert _kinds(diff.changes) == ["python_requires_changed"]
        assert diff.changes[0].after == "not a range"

    def test_missing_on_both_sides(self) -> None:
        a, b = _pkg(python_requires=None), _pkg(python_requires="")
        assert diff_packages(a, b).changes == ()


class TestDependencies:
    def test_added_and_removed(self) -> None:
        b = _pkg(dependencies=["asgiref>=3.8.1", "tzdata"])
        changes = diff_packages(_pkg(), b).in_group("dependencies")
        assert changes == [
            Change(
                "dependencies",
                "dependency_removed",
                "sqlparse",
                "sqlparse>=0.3.1",
                None,
            ),
            Change("dependencies", "dependency_added", "tzdata", None, "tzdata"),
        ]

    def test_specifier_change_is_structured(self) -> None:
        b = _pkg(dependencies=["asgiref>=3.9.1", "sqlparse>=0.3.1"])
        assert diff_packages(_pkg(), b).in_group("dependencies") == [
            Change(
                "dependencies",
                "dependency_specifier_changed",
                "asgiref",
                ">=3.8.1",
                ">=3.9.1",
            )
        ]

    def test_marker_change(self) -> None:
        a = _pkg(dependencies=["tzdata; sys_platform == 'win32'"])
        b = _pkg(dependencies=["tzdata; sys_platform != 'linux'"])
        changes = diff_packages(a, b).in_group("dependencies")
        assert _kinds(changes) == ["dependency_marker_changed"]
        assert changes[0].before == 'sys_platform == "win32"'
        assert changes[0].after == 'sys_platform != "linux"'

    def test_extras_change(self) -> None:
        a = _pkg(dependencies=["httpx[http2]>=0.27"])
        b = _pkg(dependencies=["httpx[brotli,http2]>=0.27"])
        changes = diff_packages(a, b).in_group("dependencies")
        assert changes == [
            Change(
                "dependencies",
                "dependency_extras_changed",
                "httpx",
                ["http2"],
                ["brotli", "http2"],
            )
        ]

    def test_specifier_and_marker_change_together(self) -> None:
        a = _pkg(dependencies=["tzdata>=1; sys_platform == 'win32'"])
        b = _pkg(dependencies=["tzdata>=2; os_name == 'nt'"])
        changes = diff_packages(a, b).in_group("dependencies")
        assert _kinds(changes) == [
            "dependency_specifier_changed",
            "dependency_marker_changed",
        ]

    def test_formatting_differences_are_not_changes(self) -> None:
        a = _pkg(
            dependencies=[
                "Foo_Bar >= 1.0 , < 2",
                "baz[B,a] ; python_version<'3.12'",
                "qux>=1.0.0",
            ]
        )
        b = _pkg(
            dependencies=[
                "qux>=1.0",
                "foo-bar<2,>=1.0",
                'BAZ[a,b]; python_version < "3.12"',
            ]
        )
        assert diff_packages(a, b).in_group("dependencies") == []

    def test_extra_gated_entries_are_separate_slots(self) -> None:
        a = _pkg(dependencies=["argon2-cffi>=19; extra == 'argon2'"])
        b = _pkg(dependencies=["argon2-cffi>=21; extra == 'Argon2'"])
        changes = diff_packages(a, b).in_group("dependencies")
        assert changes == [
            Change(
                "dependencies",
                "dependency_specifier_changed",
                "argon2-cffi (extra: argon2)",
                ">=19",
                ">=21",
            )
        ]

    def test_entry_gated_on_several_extras(self) -> None:
        a = _pkg(dependencies=["rich; extra == 'cli' or extra == 'Full'"])
        b = _pkg(dependencies=["rich>=13; extra == 'full' or extra == 'cli'"])
        changes = diff_packages(a, b).in_group("dependencies")
        assert [(c.kind, c.subject) for c in changes] == [
            ("dependency_specifier_changed", "rich (extra: cli, full)"),
            ("dependency_marker_changed", "rich (extra: cli, full)"),
        ]

    def test_multiple_marker_branches_diff_as_sets(self) -> None:
        a = _pkg(
            dependencies=[
                "numpy>=1.26; python_version < '3.13'",
                "numpy>=2.1; python_version >= '3.13'",
            ]
        )
        b = _pkg(
            dependencies=[
                "numpy>=1.26; python_version < '3.13'",
                "numpy>=2.2; python_version >= '3.13'",
            ]
        )
        changes = diff_packages(a, b).in_group("dependencies")
        assert _kinds(changes) == ["dependency_removed", "dependency_added"]
        assert changes[0].before == 'numpy>=2.1; python_version >= "3.13"'
        assert changes[1].after == 'numpy>=2.2; python_version >= "3.13"'

    def test_direct_url_change(self) -> None:
        a = _pkg(dependencies=["pkg @ https://example.com/pkg-1.whl"])
        b = _pkg(dependencies=["pkg @ https://example.com/pkg-2.whl"])
        assert diff_packages(a, b).in_group("dependencies") == [
            Change(
                "dependencies",
                "dependency_url_changed",
                "pkg",
                "https://example.com/pkg-1.whl",
                "https://example.com/pkg-2.whl",
            )
        ]

    def test_url_change_is_not_hidden_by_a_specifier_change(self) -> None:
        """Moving to a direct reference changes the install source."""
        a = _pkg(dependencies=["pkg>=1"])
        b = _pkg(dependencies=["pkg @ https://example.com/pkg.whl"])
        assert diff_packages(a, b).in_group("dependencies") == [
            Change(
                "dependencies",
                "dependency_url_changed",
                "pkg",
                None,
                "https://example.com/pkg.whl",
            ),
            Change("dependencies", "dependency_specifier_changed", "pkg", ">=1", "any"),
        ]

    def test_url_change_is_not_hidden_by_a_marker_change(self) -> None:
        a = _pkg(dependencies=["pkg @ https://example.com/a.whl ; os_name == 'nt'"])
        b = _pkg(dependencies=["pkg @ https://example.com/b.whl ; os_name == 'posix'"])
        kinds = _kinds(diff_packages(a, b).in_group("dependencies"))
        assert kinds == ["dependency_url_changed", "dependency_marker_changed"]

    def test_unparsable_entry_is_kept_verbatim(self) -> None:
        a = _pkg(dependencies=["not a requirement !!"])
        changes = diff_packages(a, _pkg(dependencies=[])).in_group("dependencies")
        assert changes == [
            Change(
                "dependencies",
                "dependency_removed",
                "not a requirement !!",
                "not a requirement !!",
                None,
            )
        ]


class TestExtras:
    def test_reversed_extra_comparison_is_seen(self) -> None:
        a = _pkg(dependencies=['pytest; "dev" == extra'])
        b = _pkg(dependencies=[])
        diff = diff_packages(a, b)
        assert [c.subject for c in diff.in_group("dependencies")] == [
            "pytest (extra: dev)"
        ]
        assert diff.in_group("extras") == [
            Change("extras", "extra_removed", "dev", "dev", None)
        ]

    def test_every_extra_in_a_marker_is_seen(self) -> None:
        a = _pkg(dependencies=["rich; extra == 'cli'"])
        b = _pkg(dependencies=["rich; extra == 'cli' or extra == 'full'"])
        assert diff_packages(a, b).in_group("extras") == [
            Change("extras", "extra_added", "full", None, "full")
        ]

    def test_extras_added_and_removed(self) -> None:
        a = _pkg(dependencies=["bcrypt; extra == 'bcrypt'"])
        b = _pkg(dependencies=["argon2-cffi; extra == 'argon2'"])
        assert diff_packages(a, b).in_group("extras") == [
            Change("extras", "extra_removed", "bcrypt", "bcrypt", None),
            Change("extras", "extra_added", "argon2", None, "argon2"),
        ]


class TestLicense:
    def test_canonical_expression_is_not_a_change(self) -> None:
        a = _pkg(license="mit or apache-2.0")
        b = _pkg(license="MIT OR Apache-2.0")
        assert diff_packages(a, b).changes == ()

    def test_change(self) -> None:
        b = _pkg(license="MIT")
        assert diff_packages(_pkg(), b).changes == (
            Change("license", "license_changed", "license", "BSD-3-Clause", "MIT"),
        )

    def test_legacy_to_expression(self) -> None:
        a = _pkg(license="BSD", license_source="legacy")
        diff = diff_packages(a, _pkg())
        assert _kinds(diff.changes) == ["license_changed"]

    def test_same_license_moved_to_an_expression_is_not_a_change(self) -> None:
        a = _pkg(license="BSD-3-Clause", license_source="legacy")
        assert diff_packages(a, _pkg()).changes == ()

    def test_missing_license(self) -> None:
        a = _pkg(license=None, license_source=None)
        assert diff_packages(a, _pkg()).changes[0].before is None


def _vuln(
    vid: str, *aliases: str, fixed: tuple[str, ...] = ("5.2.1",)
) -> Vulnerability:
    return Vulnerability(vid, list(aliases), f"{vid} summary", list(fixed))


class TestVulnerabilities:
    def test_added_and_removed(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("PYSEC-1")])
        b = _pkg(vulnerabilities=[_vuln("PYSEC-2", fixed=())])
        assert diff_packages(a, b).in_group("vulnerabilities") == [
            Change(
                "vulnerabilities",
                "vulnerability_removed",
                "PYSEC-1",
                {"summary": "PYSEC-1 summary", "fixed_in": ["5.2.1"], "severity": None},
                None,
            ),
            Change(
                "vulnerabilities",
                "vulnerability_added",
                "PYSEC-2",
                None,
                {"summary": "PYSEC-2 summary", "fixed_in": [], "severity": None},
            ),
        ]

    def test_matched_by_alias(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("PYSEC-1", "CVE-1")])
        b = _pkg(vulnerabilities=[_vuln("GHSA-1", "CVE-1")])
        assert diff_packages(a, b).in_group("vulnerabilities") == []

    def test_fixed_versions_changed(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("PYSEC-1")])
        b = _pkg(vulnerabilities=[_vuln("PYSEC-1", fixed=("5.2.1", "6.0.1"))])
        assert diff_packages(a, b).in_group("vulnerabilities") == [
            Change(
                "vulnerabilities",
                "vulnerability_fixed_in_changed",
                "PYSEC-1",
                ["5.2.1"],
                ["5.2.1", "6.0.1"],
            )
        ]

    def test_aliases_on_the_after_side_are_one_advisory(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("CVE-1")])
        b = _pkg(vulnerabilities=[_vuln("GHSA-1", "CVE-1"), _vuln("PYSEC-1", "CVE-1")])
        assert diff_packages(a, b).in_group("vulnerabilities") == []

    def test_aliases_on_the_before_side_are_one_advisory(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("GHSA-1", "CVE-1"), _vuln("PYSEC-1", "CVE-1")])
        b = _pkg(vulnerabilities=[_vuln("CVE-1")])
        assert diff_packages(a, b).in_group("vulnerabilities") == []

    def test_aliases_are_linked_transitively(self) -> None:
        """``A~B`` on one side and ``B~C`` on the other are the same advisory."""
        a = _pkg(vulnerabilities=[_vuln("A", "B")])
        b = _pkg(vulnerabilities=[_vuln("C", "B")])
        assert diff_packages(a, b).in_group("vulnerabilities") == []

    def test_fixes_are_merged_across_aliases(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("GHSA-1", "CVE-1", fixed=("5.2.1",))])
        b = _pkg(
            vulnerabilities=[
                _vuln("GHSA-1", "CVE-1", fixed=("5.2.1",)),
                _vuln("PYSEC-1", "CVE-1", fixed=("6.0.1",)),
            ]
        )
        assert diff_packages(a, b).in_group("vulnerabilities") == [
            Change(
                "vulnerabilities",
                "vulnerability_fixed_in_changed",
                "GHSA-1",
                ["5.2.1"],
                ["5.2.1", "6.0.1"],
            )
        ]

    def test_skipped_osv_makes_an_installed_package_unknown(self) -> None:
        local = _pkg(source="local")
        diff = diff_packages(local, _pkg(), osv_skipped=True)
        assert [(e.group, e.reason) for e in diff.unknown] == [
            ("vulnerabilities", "advisory lookup skipped for django (--no-osv)")
        ]

    def test_skipped_osv_still_compares_pypi_advisories(self) -> None:
        a = _pkg(vulnerabilities=[_vuln("PYSEC-1")])
        diff = diff_packages(a, _pkg(), osv_skipped=True)
        assert diff.unknown == ()
        assert _kinds(diff.in_group("vulnerabilities")) == ["vulnerability_removed"]

    def test_failed_lookup_is_unknown_not_removed(self) -> None:
        failed = _pkg(
            enrichment_failures=[
                EnrichmentFailure("osv", "timed out", VULNERABILITY_FIELD)
            ]
        )
        diff = diff_packages(_pkg(vulnerabilities=[_vuln("PYSEC-1")]), failed)
        assert diff.in_group("vulnerabilities") == []
        assert [entry.group for entry in diff.unknown] == ["vulnerabilities"]
        assert "django" in diff.unknown[0].reason


def _file(filename: str, **over: object) -> ArtifactFile:
    kind = "wheel" if filename.endswith(".whl") else "sdist"
    tags = () if kind == "sdist" else (filename.removesuffix(".whl").split("-", 2)[2],)
    base = ArtifactFile(
        filename=filename,
        url=f"https://files.example/{filename}",
        kind=kind,
        compatibility=Compatibility(compatible=True),
        size=1000,
        upload_time="2026-04-01T10:00:00Z",
        sha256="a" * 64,
        tags=tags,
    )
    return replace(base, **over)


def _evidence(version: str, *files: ArtifactFile) -> ReleaseEvidence:
    release = ReleaseArtifacts("django", version, Target(), list(files))
    return ReleaseEvidence(release=release)


class TestArtifacts:
    def test_not_requested_leaves_artifact_groups_out(self) -> None:
        diff = diff_packages(_pkg(), _pkg())
        assert diff.in_group("artifacts") == []
        assert diff.unknown == ()

    def test_files_pair_by_slot_across_versions(self) -> None:
        a = _evidence(
            "5.2", _file("django-5.2-py3-none-any.whl"), _file("django-5.2.tar.gz")
        )
        b = _evidence(
            "6.0",
            _file("django-6.0-py3-none-any.whl", sha256="b" * 64, size=1200),
            _file("django-6.0.tar.gz", sha256="c" * 64),
        )
        diff = diff_packages(_pkg(), _pkg(version="6.0"), a_release=a, b_release=b)
        changes = diff.in_group("artifacts")
        # Paired by slot, so nothing is "added" or "removed"; new digests and
        # sizes on new filenames are recorded, but only as expected.
        assert [(c.kind, c.subject) for c in changes] == [
            ("artifact_hash_changed", "sdist .tar.gz"),
            ("artifact_hash_changed", "wheel py3-none-any"),
            ("artifact_size_changed", "wheel py3-none-any"),
        ]
        assert all(change.expected for change in changes)

    def test_size_change_on_the_same_filename_is_not_expected(self) -> None:
        a = _evidence("5.2", _file("django-5.2.tar.gz"))
        b = _evidence("5.2", _file("django-5.2.tar.gz", size=2000))
        changes = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b).in_group(
            "artifacts"
        )
        assert changes == [
            Change("artifacts", "artifact_size_changed", "sdist .tar.gz", 1000, 2000)
        ]
        assert changes[0].expected is False

    def test_added_and_removed_slots(self) -> None:
        a = _evidence("5.2", _file("django-5.2.tar.gz"))
        b = _evidence("6.0", _file("django-6.0-py3-none-any.whl"))
        changes = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b).in_group(
            "artifacts"
        )
        assert changes == [
            Change(
                "artifacts",
                "artifact_removed",
                "sdist .tar.gz",
                "django-5.2.tar.gz",
                None,
            ),
            Change(
                "artifacts",
                "artifact_added",
                "wheel py3-none-any",
                None,
                "django-6.0-py3-none-any.whl",
            ),
        ]

    def test_each_sdist_format_is_its_own_slot(self) -> None:
        """Both archive formats pair with their own, whatever the listing order."""
        a = _evidence("1.0", _file("pkg-1.0.tar.gz"), _file("pkg-1.0.zip"))
        b = _evidence(
            "2.0", _file("pkg-2.0.zip", sha256="b" * 64), _file("pkg-2.0.tar.gz")
        )
        changes = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b).in_group(
            "artifacts"
        )
        assert [(c.kind, c.subject, c.expected) for c in changes] == [
            ("artifact_hash_changed", "sdist .zip", True)
        ]

    def test_build_tagged_wheels_pair_with_the_same_build(self) -> None:
        a = _evidence(
            "1.0",
            _file("pkg-1.0-1-py3-none-any.whl", tags=("py3-none-any",)),
            _file("pkg-1.0-2-py3-none-any.whl", tags=("py3-none-any",)),
        )
        b = _evidence(
            "2.0",
            _file("pkg-2.0-2-py3-none-any.whl", tags=("py3-none-any",), size=5),
            _file("pkg-2.0-1-py3-none-any.whl", tags=("py3-none-any",)),
        )
        changes = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b).in_group(
            "artifacts"
        )
        assert [(c.kind, c.subject, c.expected) for c in changes] == [
            ("artifact_size_changed", "wheel py3-none-any build 2", True)
        ]

    def test_hash_change_on_the_same_filename(self) -> None:
        a = _evidence("5.2", _file("django-5.2.tar.gz"))
        b = _evidence("5.2", _file("django-5.2.tar.gz", sha256="b" * 64))
        changes = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b).in_group(
            "artifacts"
        )
        assert changes == [
            Change(
                "artifacts",
                "artifact_hash_changed",
                "sdist .tar.gz",
                "a" * 64,
                "b" * 64,
            )
        ]

    def test_size_yanked_compatibility_and_provenance(self) -> None:
        a = _evidence("5.2", _file("django-5.2-py3-none-any.whl"))
        b = _evidence(
            "6.0",
            _file(
                "django-6.0-py3-none-any.whl",
                size=2000,
                yanked=True,
                compatibility=Compatibility(compatible=False, reason="python"),
                provenance_url="https://pypi.example/provenance",
            ),
        )
        diff = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b)
        assert [(c.kind, c.expected) for c in diff.in_group("artifacts")] == [
            ("artifact_size_changed", True),
            ("artifact_yanked_changed", False),
            ("artifact_compatibility_changed", False),
        ]
        assert _kinds(diff.in_group("artifacts")) == [
            "artifact_size_changed",
            "artifact_yanked_changed",
            "artifact_compatibility_changed",
        ]
        assert diff.in_group("provenance") == [
            Change(
                "provenance",
                "provenance_changed",
                "wheel py3-none-any",
                before=False,
                after=True,
            )
        ]

    def test_release_date(self) -> None:
        a = _evidence("5.2", _file("django-5.2.tar.gz"))
        b = _evidence(
            "6.0",
            _file("django-6.0.tar.gz", upload_time="2026-12-03T09:00:00Z"),
            _file("django-6.0-py3-none-any.whl", upload_time="2026-12-02T09:00:00Z"),
        )
        diff = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b)
        assert diff.in_group("release") == [
            Change(
                "release",
                "release_date_changed",
                "release_date",
                "2026-04-01",
                "2026-12-02",
            )
        ]

    def test_missing_listing_is_unknown(self) -> None:
        a = _evidence("5.2", _file("django-5.2.tar.gz"))
        b = ReleaseEvidence(reason="django 6.0: network down")
        diff = diff_packages(_pkg(), _pkg(), a_release=a, b_release=b)
        assert diff.in_group("artifacts") == []
        assert [(e.group, e.reason) for e in diff.unknown] == [
            ("artifacts", "django 6.0: network down"),
            ("provenance", "django 6.0: network down"),
        ]


def test_changes_are_ordered_by_group() -> None:
    a = _pkg(license="MIT")
    b = _pkg(version="6.0", python_requires=">=3.12", dependencies=["asgiref"])
    groups = [change.group for change in diff_packages(a, b).changes]
    assert groups == ["release", "python", "dependencies", "dependencies", "license"]
