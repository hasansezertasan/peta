"""Adapters wrapping peta's built-in enrichment sources as providers.

Each adapter owns its own failure and configuration handling, so orchestration
neither catches source-specific exceptions nor reads source-specific settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from peta.core import osv, stats
from peta.core.output import utc_now
from peta.core.providers.base import (
    CountEvidence,
    ProviderResult,
    VulnerabilityEvidence,
)
from peta.core.validation import EnrichmentError

if TYPE_CHECKING:
    from peta.core.models import PackageInfo
    from peta.core.providers.base import Capability, EnrichmentProvider, ProviderGroup

__all__ = [
    "DEFAULT_PROVIDERS",
    "LibrariesIoProvider",
    "OsvProvider",
    "PypiStatsProvider",
]


def _failure(
    provider: str, capability: Capability, subject: str, exc: EnrichmentError
) -> ProviderResult:
    return ProviderResult(
        provider=provider,
        capability=capability,
        state="failed",
        subject=subject,
        retrieved_at=utc_now(),
        reason=exc.reason,
    )


@dataclass(frozen=True)
class OsvProvider:
    """Look up advisories for a package on OSV.dev."""

    name: str = osv.OSV_SOURCE
    capability: Capability = "vulnerabilities"
    group: ProviderGroup = "vulnerabilities"

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Query OSV for the package's known vulnerabilities.

        Returns:
            The advisories found, an empty answer, or the lookup failure.
        """
        try:
            vulnerabilities = osv.get_vulnerabilities(pkg.name, pkg.version)
        except EnrichmentError as exc:
            return _failure(self.name, self.capability, pkg.name, exc)
        return ProviderResult(
            provider=self.name,
            capability=self.capability,
            state="success" if vulnerabilities else "empty",
            subject=pkg.name,
            retrieved_at=utc_now(),
            evidence=VulnerabilityEvidence(vulnerabilities),
        )


@dataclass(frozen=True)
class PypiStatsProvider:
    """Look up a package's last-month download count on pypistats.org."""

    name: str = stats.PYPISTATS_SOURCE
    capability: Capability = "download_count"
    group: ProviderGroup = "stats"

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Query pypistats.org for the package's recent downloads.

        Returns:
            The download count, an empty answer, or the lookup failure.
        """
        try:
            count = stats.get_download_count(pkg.name)
        except EnrichmentError as exc:
            return _failure(self.name, self.capability, pkg.name, exc)
        return ProviderResult(
            provider=self.name,
            capability=self.capability,
            state="empty" if count is None else "success",
            subject=pkg.name,
            retrieved_at=utc_now(),
            evidence=None if count is None else CountEvidence(count),
        )


@dataclass(frozen=True)
class LibrariesIoProvider:
    """Look up a package's dependent count on libraries.io."""

    name: str = stats.LIBRARIES_IO_SOURCE
    capability: Capability = "dependent_count"
    group: ProviderGroup = "stats"

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Query libraries.io for the package's dependent count.

        Reports ``unavailable`` without making a request when no API key is
        configured, keeping "not set up" distinct from "returned nothing".

        Returns:
            The dependent count, an empty or unavailable answer, or the
            lookup failure.
        """
        api_key = stats.libraries_io_api_key()
        if api_key is None:
            return ProviderResult(
                provider=self.name,
                capability=self.capability,
                state="unavailable",
                subject=pkg.name,
                reason="LIBRARIES_IO_API_KEY is not configured",
            )
        try:
            count = stats.get_dependent_count(pkg.name, api_key=api_key)
        except EnrichmentError as exc:
            return _failure(self.name, self.capability, pkg.name, exc)
        return ProviderResult(
            provider=self.name,
            capability=self.capability,
            state="empty" if count is None else "success",
            subject=pkg.name,
            retrieved_at=utc_now(),
            evidence=None if count is None else CountEvidence(count),
        )


DEFAULT_PROVIDERS: tuple[EnrichmentProvider, ...] = (
    OsvProvider(),
    PypiStatsProvider(),
    LibrariesIoProvider(),
)
"""The built-in providers, in the order orchestration consults them.

Order is the conflict tie-breaker: for a given capability the first provider to
return evidence wins.
"""
