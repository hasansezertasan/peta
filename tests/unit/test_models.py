"""Unit tests for core data models."""

import pytest

from peta.core.models import DependencyNode, PackageInfo, Vulnerability

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
        assert pkg.dependencies == []
        assert pkg.vulnerabilities == []

    def test_defaults(self) -> None:
        pkg = PackageInfo(name="t", version="1.0", source="remote")
        assert pkg.author is None
        assert pkg.project_urls == {}
        assert pkg.classifiers == []
        assert pkg.keywords == []
        assert pkg.files is None


class TestDependencyNode:
    def test_defaults(self) -> None:
        node = DependencyNode(name="urllib3", version_spec=">=1.21.1")
        assert node.installed_version is None
        assert node.children == []
        assert node.circular is False

    def test_full(self) -> None:
        child = DependencyNode(name="idna", version_spec="")
        node = DependencyNode(
            name="requests",
            version_spec="==2.31.0",
            installed_version="2.31.0",
            children=[child],
            circular=False,
        )
        assert node.children == [child]
