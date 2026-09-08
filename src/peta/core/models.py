"""Core data models for peta."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from peta.core.cache import Freshness
    from peta.core.output import SourceRecord

__all__ = [
    "VULNERABILITY_FIELD",
    "DependencyNode",
    "DependencyResolutionFailure",
    "EnrichmentFailure",
    "PackageInfo",
    "ProviderConflict",
    "ProviderWarning",
    "Vulnerability",
]


VULNERABILITY_FIELD = "result.vulnerabilities"
"""The ``result`` path advisory evidence is written to.

Declared here rather than in :mod:`peta.core.providers` so a package can be
asked whether its advisory lookup failed without importing the provider layer.
"""


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
    field: str | None
    """The ``result`` path the failed source would have written to.

    Required but nullable, so a failure always states *what* is missing —
    including stating explicitly that it cannot be attributed to a result
    field, rather than leaving that to a forgotten default.
    """


@dataclass(frozen=True)
class ProviderWarning:
    """An advisory message a provider returned alongside its evidence."""

    source: str
    code: str
    message: str


@dataclass(frozen=True)
class ProviderConflict:
    """Two providers offered different evidence for the same field.

    Both sources are named so the disagreement stays visible; ``kept`` records
    which one the deterministic merge order selected.
    """

    field: str
    kept: str
    discarded: str

    @property
    def description(self) -> str:
        """Human-readable summary of the disagreement.

        Returns:
            The single-source conflict reason used by every output renderer.
        """
        return f"kept {self.kept}, discarded conflicting {self.discarded}"


@dataclass(frozen=True)
class DependencyResolutionFailure:
    """A failed or unavailable transitive dependency lookup."""

    source: str
    state: Literal["empty", "unavailable", "failed"]
    reason: str
    retrieved_at: str | None
    """When the source answered, or ``None`` if it was never contacted.

    Required but nullable, so a failure always states whether a retrieval
    happened at all rather than leaving it to a forgotten default. An offline
    miss deliberately makes no request, and claiming a retrieval time for one
    would make the provenance misleading.
    """
    freshness: Freshness | None = None
    """Where the answer came from, when there was one.

    An ``empty`` result is a completed retrieval — the source was asked and
    holds nothing — so it reports its origin like any other completed
    lookup. A failure or an offline refusal has no origin to report.
    """


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
    enrichment_conflicts: list[ProviderConflict] = field(default_factory=list)
    provider_warnings: list[ProviderWarning] = field(default_factory=list)
    retrieved_at: str | None = None
    freshness: Freshness | None = None
    """Where the metadata came from: the source, or peta's cache.

    ``None`` for a package read from the installed environment, which has no
    retrieval to be fresh or stale relative to.
    """
    enrichment_sources: list[SourceRecord] = field(default_factory=list)

    @property
    def vulnerabilities_unknown(self) -> bool:
        """Whether the advisory lookup failed, leaving the count unknown.

        Derived from the failed field rather than a provider name, so an
        alternate advisory source is never reported as a clean zero.

        Returns:
            ``True`` when a source that supplies advisories failed.
        """
        return any(
            failure.field == VULNERABILITY_FIELD for failure in self.enrichment_failures
        )


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
    freshness: Freshness | None = None
    """Where this node's metadata came from: the source, or peta's cache.

    Carried per node because a tree can be assembled from a mix — some
    dependencies served from cache, others fetched — so one figure for the
    whole command would be a fiction.
    """
    resolution_failure: DependencyResolutionFailure | None = None
