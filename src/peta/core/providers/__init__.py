"""Enrichment provider interfaces and the built-in source adapters."""

from __future__ import annotations

from peta.core.providers.base import (
    CAPABILITY_FIELDS,
    CAPABILITY_GROUPS,
    Capability,
    CountEvidence,
    EnrichmentProvider,
    Evidence,
    ProviderGroup,
    ProviderResult,
    VulnerabilityEvidence,
)
from peta.core.providers.builtin import (
    DEFAULT_PROVIDERS,
    LibrariesIoProvider,
    OsvProvider,
    PypiStatsProvider,
)

__all__ = [
    "CAPABILITY_FIELDS",
    "CAPABILITY_GROUPS",
    "DEFAULT_PROVIDERS",
    "Capability",
    "CountEvidence",
    "EnrichmentProvider",
    "Evidence",
    "LibrariesIoProvider",
    "OsvProvider",
    "ProviderGroup",
    "ProviderResult",
    "PypiStatsProvider",
    "VulnerabilityEvidence",
]
