"""Unit tests for release artifact inspection and compatibility evaluation."""

import sys
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from packaging.tags import sys_tags

from peta.core.artifacts import (
    Target,
    _artifact,
    _Lookup,
    _merged_retrieval,
    evaluate_compatibility,
    get_release,
    parse_target,
)
from peta.core.cache import Provenance
from peta.core.index import files_for_version, latest_version
from tests.contract_fixtures import load_contract

if TYPE_CHECKING:
    from peta.core.cache import Freshness
    from peta.core.index import IndexFile, ProjectPage
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit

_HERE = Target()
"""The running interpreter, which is what an unqualified query judges against."""

_NATIVE_WHEEL = f"pkg-1.0-{next(iter(sys_tags()))}.whl"
"""A platform wheel built for this exact machine, whatever machine runs the suite."""

_FOREIGN_WHEEL = "pkg-1.0-cp313-cp313-nonexistent_platform.whl"
"""A well-formed wheel whose platform no interpreter anywhere accepts."""


def _file(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "filename": "pkg-1.0-py3-none-any.whl",
        "url": "https://files.invalid/pkg-1.0-py3-none-any.whl",
        "hashes": {"sha256": "abc123"},
        "requires-python": ">=3.8",
        "size": 1024,
        "upload-time": "2026-01-02T03:04:05Z",
        "core-metadata": True,
    }
    return base | over


def _page(
    *files: dict[str, object], versions: list[str] | None = None
) -> dict[str, object]:
    return {
        "meta": {"api-version": "1.1"},
        "name": "pkg",
        "versions": versions or ["1.0"],
        "files": list(files),
    }


class TestCompatibility:
    def test_pure_python_wheel_fits_anywhere(self) -> None:
        result = evaluate_compatibility("pkg-1.0-py3-none-any.whl", ">=3.8", _HERE)
        assert result.compatible is True
        assert result.reason is None

    def test_platform_wheel_for_this_machine_fits(self) -> None:
        assert evaluate_compatibility(_NATIVE_WHEEL, None, _HERE).compatible is True

    def test_platform_wheel_for_another_machine_does_not(self) -> None:
        result = evaluate_compatibility(_FOREIGN_WHEEL, None, _HERE)
        assert result.compatible is False
        assert "no wheel tag matches" in (result.reason or "")

    def test_sdist_is_decided_by_requires_python_alone(self) -> None:
        result = evaluate_compatibility("pkg-1.0.tar.gz", ">=3.8", _HERE)
        assert result.compatible is True

    def test_requires_python_excludes_the_target(self) -> None:
        result = evaluate_compatibility(
            "pkg-1.0-py3-none-any.whl", ">=3.99", Target("3.13")
        )
        assert result.compatible is False
        assert result.reason == "Python 3.13 is outside >=3.99"

    def test_requires_python_admits_the_target(self) -> None:
        result = evaluate_compatibility(
            "pkg-1.0-py3-none-any.whl", ">=3.8,<4", Target("3.13")
        )
        assert result.compatible is True

    def test_unreadable_requires_python_is_unknown_not_incompatible(self) -> None:
        result = evaluate_compatibility("pkg-1.0-py3-none-any.whl", "not-a-spec", _HERE)
        assert result.compatible is None
        assert "unreadable Requires-Python" in (result.reason or "")

    def test_unreadable_wheel_filename_is_unknown(self) -> None:
        result = evaluate_compatibility("not-a-wheel-name.whl", None, _HERE)
        assert result.compatible is None
        assert "unreadable wheel filename" in (result.reason or "")

    def test_an_explicit_target_is_not_stricter_than_the_running_one(self) -> None:
        # ``cpXY-none-any`` is in sys_tags but in neither cpython_tags nor a
        # plain compatible_tags, so the same wheel used to be installable
        # under the default target and rejected under --python <same version>.
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        wheel = (
            f"pkg-1.0-cp{sys.version_info.major}{sys.version_info.minor}-none-any.whl"
        )
        assert evaluate_compatibility(wheel, None, _HERE).compatible is True
        assert evaluate_compatibility(wheel, None, Target(running)).compatible is True

    def test_target_defaults_to_the_running_interpreter(self) -> None:
        assert Target().version == __import__("platform").python_version()

    def test_parse_target_accepts_a_version_and_none(self) -> None:
        assert parse_target(None) == Target()
        assert parse_target("3.13").version == "3.13"

    @pytest.mark.parametrize(
        "value",
        # "3.¹³" and "3.١٣" are ``str.isdigit()`` true but ``int()`` refuses
        # them, so a digit check alone lets them through to a crash.
        [
            "3",
            "x.y",
            "",
            "3.13.",
            "3.13.bad",
            "3.13.4.5",
            "3..1",
            "3.\u00b9\u00b3",
            "3.\u0661\u0663",
        ],
    )
    def test_parse_target_rejects_nonsense(self, value: str) -> None:
        with pytest.raises(ValueError, match="Invalid Python version"):
            _ = parse_target(value)


class TestClassification:
    """Files the index matched but neither parser recognizes stay unlabeled.

    Reached directly because the page filter upstream only matches filenames
    it could parse a version from; these guards exist so a future widening of
    that filter cannot silently mislabel a file as a source distribution.
    """

    def test_an_unknown_extension_is_neither_wheel_nor_sdist(self) -> None:
        entry: IndexFile = {
            "filename": "pkg-1.0-py3.7.egg",
            "url": "https://files.invalid/x",
        }
        assert _artifact(entry, _HERE).kind == "other"

    def test_an_unreadable_wheel_name_yields_no_tags(self) -> None:
        entry: IndexFile = {
            "filename": "not-a-wheel-name.whl",
            "url": "https://files.invalid/x",
        }
        artifact = _artifact(entry, _HERE)
        assert artifact.tags == ()
        assert artifact.compatibility.compatible is None


class TestReleaseSelection:
    def test_latest_prefers_a_final_release_over_a_prerelease(self) -> None:
        assert latest_version(["1.0", "2.0rc1", "1.5"]) == "1.5"

    def test_latest_falls_back_when_every_version_is_a_prerelease(self) -> None:
        assert latest_version(["1.0rc1", "2.0rc1"]) == "2.0rc1"

    def test_files_for_a_non_pep440_version_is_empty(self) -> None:
        page: ProjectPage = {"name": "pkg", "versions": ["weird"], "files": []}
        assert files_for_version(page, "weird") == []

    def test_files_match_across_equivalent_version_spellings(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=_page(_file(filename="pkg-1.0.0-py3-none-any.whl")))
        release, _ = get_release("pkg", "1.0")
        assert release is not None
        assert [f.filename for f in release.files] == ["pkg-1.0.0-py3-none-any.whl"]


class TestGetRelease:
    def test_an_unpublished_version_is_not_an_empty_release(
        self, fake_http: FakeTransport
    ) -> None:
        # A typo'd pin must not look like a successful answer about a real
        # release that happens to ship nothing.
        fake_http.reply(json=_page(_file(), versions=["1.0"]))
        release, _ = get_release("pkg", "99.0")
        assert release is None

    def test_a_published_version_with_no_files_is_a_real_release(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=_page(versions=["1.0"]))
        release, _ = get_release("pkg", "1.0")
        assert release is not None
        assert release.files == []

    def test_a_version_spelled_differently_still_resolves(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(
            json=_page(_file(filename="pkg-1.0-py3-none-any.whl"), versions=["1.0.0"])
        )
        release, _ = get_release("pkg", "1.0")
        assert release is not None
        assert len(release.files) == 1

    def test_a_non_pep440_version_that_is_listed_resolves(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=_page(versions=["weird"]))
        release, _ = get_release("pkg", "weird")
        assert release is not None

    def test_a_non_pep440_version_that_is_not_listed_does_not(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=_page(versions=["1.0"]))
        release, _ = get_release("pkg", "weird")
        assert release is None

    def test_unknown_package_has_no_release(self, fake_http: FakeTransport) -> None:
        fake_http.reply(status=404)
        release, provenance = get_release("nope-xyz")
        assert release is None
        assert provenance.freshness == "live"

    def test_reads_every_field_the_index_supplies(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(
            json=_page(
                _file(provenance="https://pypi.org/integrity/pkg/1.0/whl/provenance")
            )
        )
        release, _ = get_release("pkg")
        assert release is not None
        file = release.files[0]
        assert file.kind == "wheel"
        assert file.size == 1024
        assert file.sha256 == "abc123"
        assert file.upload_time == "2026-01-02T03:04:05Z"
        assert file.requires_python == ">=3.8"
        assert file.core_metadata is True
        assert file.tags == ("py3-none-any",)
        assert file.provenance_url is not None
        assert file.publishers == ()

    def test_summarizes_wheels_sdists_sizes_and_yanks(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(
            json=_page(
                _file(),
                _file(filename="pkg-1.0.tar.gz", size=2048, yanked="broken build"),
                _file(filename="pkg-1.0-py3-none-any.egg", size=None),
            )
        )
        release, _ = get_release("pkg")
        assert release is not None
        assert len(release.wheels) == 1
        assert len(release.sdists) == 1
        assert release.total_size == 3072
        assert release.yanked is False
        sdist = release.sdists[0]
        assert sdist.yanked is True
        assert sdist.yanked_reason == "broken build"

    def test_a_fully_yanked_release_says_so(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json=_page(_file(yanked=True)))
        release, _ = get_release("pkg")
        assert release is not None
        assert release.yanked is True
        assert release.files[0].yanked_reason is None

    def test_missing_optional_fields_become_unknown_not_wrong(
        self, fake_http: FakeTransport
    ) -> None:
        bare: dict[str, object] = {
            "filename": "pkg-1.0-py3-none-any.whl",
            "url": "https://files.invalid/pkg-1.0-py3-none-any.whl",
        }
        fake_http.reply(json=_page(bare))
        release, _ = get_release("pkg")
        assert release is not None
        file = release.files[0]
        assert file.size is None
        assert file.sha256 is None
        assert file.upload_time is None
        assert file.requires_python is None
        assert file.core_metadata is False
        assert file.provenance_url is None
        assert release.with_provenance == []

    def test_incompatible_files_are_kept_out_of_the_compatible_count(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(json=_page(_file(), _file(filename=_FOREIGN_WHEEL)))
        release, _ = get_release("pkg")
        assert release is not None
        assert len(release.files) == 2
        assert [f.filename for f in release.compatible] == ["pkg-1.0-py3-none-any.whl"]


class TestPublishers:
    def test_a_non_github_publisher_keeps_its_own_fields(
        self, fake_http: FakeTransport
    ) -> None:
        """Every publisher kind names itself differently; none may be dropped."""
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(
            url="/integrity/",
            json={
                "attestation_bundles": [
                    {
                        "publisher": {
                            "kind": "GitLab",
                            "repository": "group/project",
                            "workflow_filepath": ".gitlab-ci.yml",
                        }
                    }
                ]
            },
        )
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        (publisher,) = release.files[0].publishers
        assert publisher.claims["workflow_filepath"] == ".gitlab-ci.yml"
        assert release.publishers == [
            "GitLab repository=group/project workflow_filepath=.gitlab-ci.yml"
        ]

    def _page_with_provenance(self) -> dict[str, object]:
        return _page(
            _file(provenance="https://pypi.org/integrity/pkg/1.0/whl/provenance"),
            _file(filename="pkg-1.0.tar.gz"),
        )

    def test_reads_the_trusted_publisher_identity(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(url="/integrity/", json=load_contract("pypi-provenance.json"))
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        (publisher,) = release.files[0].publishers
        assert publisher.kind == "GitHub"
        assert publisher.claims == {
            "repository": "example-org/example-package",
            "workflow": "publish.yml",
            "environment": "release",
        }
        assert release.files[1].publishers == ()
        assert release.publisher_failures == ()
        assert release.publisher_retrieval is not None
        assert release.publisher_retrieval.freshness == "live"

    @pytest.mark.parametrize(
        "body",
        [
            {"version": 1, "attestation_bundles": []},
            {"version": 1, "attestation_bundles": [{"attestations": []}]},
            {"version": 1, "attestation_bundles": [{"publisher": {}}]},
        ],
    )
    def test_a_document_without_a_publisher_supplies_none(
        self, fake_http: FakeTransport, body: dict[str, object]
    ) -> None:
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(url="/integrity/", json=body)
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        assert release.files[0].publishers == ()
        assert release.publisher_failures == ()

    def test_every_attestation_bundle_is_read(self, fake_http: FakeTransport) -> None:
        """PEP 740 groups bundles by publisher and permits several."""
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(
            url="/integrity/",
            json={
                "attestation_bundles": [
                    {"publisher": {"kind": "GitHub", "repository": "a/b"}},
                    {"publisher": {"kind": "GitLab", "repository": "c/d"}},
                ]
            },
        )
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        assert [p.kind for p in release.files[0].publishers] == ["GitHub", "GitLab"]

    @pytest.mark.parametrize(
        "body",
        [
            {"attestation_bundles": {}},
            {"attestation_bundles": False},
            {"attestation_bundles": ""},
            {"version": 1},
        ],
    )
    def test_a_malformed_bundle_collection_is_a_failure_not_an_absence(
        self, fake_http: FakeTransport, body: dict[str, object]
    ) -> None:
        # PEP 740 makes the array required, so none of these states that no
        # publisher exists — they state that the document cannot be read.
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(url="/integrity/", json=body)
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        assert len(release.publisher_failures) == 1

    def test_claims_are_read_from_both_shapes_the_pep_allows(
        self, fake_http: FakeTransport
    ) -> None:
        """PyPI serves the identity at the top level; the PEP also nests it."""
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.reply(
            url="/integrity/",
            json={
                "attestation_bundles": [
                    {
                        "publisher": {
                            "kind": "important-ci-service",
                            "claims": {"ref": "refs/tags/v1", "sha": "abc"},
                            "vendor-property": "foo",
                            "another-property": 123,
                        }
                    }
                ]
            },
        )
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        (publisher,) = release.files[0].publishers
        assert publisher.claims == {
            "vendor-property": "foo",
            "ref": "refs/tags/v1",
            "sha": "abc",
        }

    @pytest.mark.parametrize(
        ("status", "body"), [(503, None), (200, "not json"), (200, [])]
    )
    def test_a_failed_lookup_is_reported_not_read_as_absence(
        self, fake_http: FakeTransport, status: int, body: object
    ) -> None:
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        if isinstance(body, str):
            fake_http.reply(url="/integrity/", status=status, text=body)
        else:
            fake_http.reply(url="/integrity/", status=status, json=body)
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        assert release.files[0].publishers == ()
        assert len(release.publisher_failures) == 1
        assert release.publisher_failures[0].filename == "pkg-1.0-py3-none-any.whl"

    @pytest.mark.parametrize(
        ("freshness", "expected"),
        [
            (("live", "cached"), "cached"),
            (("cached", "live"), "cached"),
            (("live", "revalidated"), "revalidated"),
            (("live", "live"), "live"),
        ],
    )
    def test_mixed_freshness_is_reported_as_the_stalest_part(
        self, freshness: tuple[str, str], expected: str
    ) -> None:
        # One record covers one request per file. If any was served from
        # disk, describing the whole of it as "live" overstates the
        # provenance this field exists to make honest.
        merged = _merged_retrieval([
            _Lookup(retrieval=Provenance(cast("Freshness", state), stamp))
            for state, stamp in zip(
                freshness, ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"), strict=True
            )
        ])
        assert merged is not None
        assert merged.freshness == expected
        assert merged.retrieved_at == "2026-01-01T00:00:00Z"

    def test_no_completed_lookup_has_no_provenance(self) -> None:
        assert _merged_retrieval([_Lookup()]) is None

    def test_a_transport_failure_does_not_abort_the_listing(
        self, fake_http: FakeTransport
    ) -> None:
        fake_http.reply(url="/simple/", json=self._page_with_provenance())
        fake_http.fail(httpx.ConnectError("refused"), url="/integrity/")
        release, _ = get_release("pkg", publishers=True)
        assert release is not None
        assert len(release.files) == 2
        assert len(release.publisher_failures) == 1
