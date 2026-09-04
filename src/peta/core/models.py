"""Core data models for peta."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from peta.core.output import SourceRecord

__all__ = [
    "DependencyNode",
    "DependencyResolutionFailure",
    "EnrichmentFailure",
    "PackageInfo",
    "Vulnerability",
]


@dataclass
class Vulnerability:
    """A known security vulnerability for a package."""

    id: str
    aliases: list[str]
    summary: str
    fixed_in: list[str]
    severity: str | None = None


@dataclass
class EnrichmentFailure:
    """A non-fatal failure from an optional metadata source."""

    source: str
    reason: str


@dataclass(frozen=True)
class DependencyResolutionFailure:
    """A failed or unavailable transitive dependency lookup."""

    source: str
    state: Literal["empty", "unavailable", "failed"]
    reason: str
    retrieved_at: str


@dataclass
class PackageInfo:
    """Package metadata from a local installation or PyPI."""

    name: str
    version: str
    source: str  # "local" or "remote"

    summary: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    license: str | None = None
    python_requires: str | None = None
    homepage: str | None = None
    project_urls: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    classifiers: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    files: list[str] | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    download_count: int | None = None
    dependent_count: int | None = None
    license_source: Literal["expression", "legacy"] | None = None
    enrichment_failures: list[EnrichmentFailure] = field(default_factory=list)
    retrieved_at: str | None = None
    enrichment_sources: list[SourceRecord] = field(default_factory=list)


@dataclass
class DependencyNode:
    """A node in a package's recursive dependency tree."""

    name: str
    version_spec: str
    installed_version: str | None = None
    children: list[DependencyNode] = field(default_factory=list)
    circular: bool = False
    source: str | None = None
    retrieved_at: str | None = None
    resolution_failure: DependencyResolutionFailure | None = None
