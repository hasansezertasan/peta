"""Unit tests for core data models."""

import pytest

from peta.core.models import (
    DependencyNode,
    DependencyResolutionFailure,
    PackageInfo,
    Vulnerability,
)

pytestmark = pytest.mark.unit


class TestVulnerability:
    def test_full(self) -> None:
        vuln = Vulnerability(
            id="PYSEC-2024-001",
            aliases=["CVE-2024-12345"],
            summary="SSRF vulnerability",
            fixed_in=["2.32.0"],
            severity="HIGH",
        )
        assert vuln.id == "PYSEC-2024-001"
        assert vuln.aliases == ["CVE-2024-12345"]
        assert vuln.fixed_in == ["2.32.0"]
        assert vuln.severity == "HIGH"

    def test_defaults(self) -> None:
        vuln = Vulnerability(id="GHSA-x", aliases=[], summary="s", fixed_in=[])
        assert vuln.severity is None


class TestPackageInfo:
    def test_minimal(self) -> None:
        pkg = PackageInfo(name="requests", version="2.31.0", source="local")
        assert pkg.name == "requests"
        assert pkg.source == "local"
        assert pkg.summary is None
        assert pkg.license_source is None
        assert pkg.dependencies == []
        assert pkg.vulnerabilities == []

    def test_defaults(self) -> None:
        pkg = PackageInfo(name="t", version="1.0", source="remote")
        assert pkg.author is None
        assert pkg.project_urls == {}
        assert pkg.classifiers == []
        assert pkg.keywords == []
        assert pkg.files is None

    def test_preserves_positional_constructor_order(self) -> None:
        pkg = PackageInfo(
            "requests",
            "2.31.0",
            "local",
            "summary",
            "author",
            "author@example.com",
            "maintainer",
            "Apache-2.0",
            ">=3.8",
            "https://example.com",
        )
        assert pkg.python_requires == ">=3.8"
        assert pkg.homepage == "https://example.com"
        assert pkg.license_source is None


class TestDependencyNode:
    def test_defaults(self) -> None:
        node = DependencyNode(name="urllib3", version_spec=">=1.21.1")
        assert node.selected_version is None
        assert node.children == []
        assert node.state == "satisfied"

    def test_full(self) -> None:
        child = DependencyNode(name="idna", version_spec="")
        node = DependencyNode(
            name="requests",
            version_spec="==2.31.0",
            selected_version="2.31.0",
            children=[child],
            state="satisfied",
        )
        assert node.children == [child]

    def test_legacy_positional_constructor_order(self) -> None:
        child = DependencyNode(name="idna", version_spec="")

        node = DependencyNode(
            "requests",
            "==2.31.0",
            "2.31.0",
            [child],
            True,  # ruff: ignore[boolean-positional-value-in-call]  # Exercise the legacy positional API.
        )

        assert node.selected_version == "2.31.0"
        assert node.installed_version == "2.31.0"
        assert node.children == [child]
        assert node.circular is True

    def test_legacy_circular_argument_translates_to_state(self) -> None:
        node = DependencyNode(name="x", version_spec="", circular=True)
        assert node.state == "circular"
        assert node.circular is True

    def test_state_precedence_over_circular(self) -> None:
        node = DependencyNode(
            name="x", version_spec="", state="conflicting", circular=True
        )
        assert node.state == "conflicting"
        assert node.circular is False

    def test_circular_false_keeps_satisfied(self) -> None:
        node = DependencyNode(name="x", version_spec="", circular=False)
        assert node.state == "satisfied"
        assert node.circular is False

    def test_legacy_resolution_failure_infers_unresolved_state(self) -> None:
        failure = DependencyResolutionFailure(
            source="pypi", state="failed", reason="down", retrieved_at=None
        )
        node = DependencyNode(name="x", version_spec="", resolution_failure=failure)
        assert node.state == "unresolved"
