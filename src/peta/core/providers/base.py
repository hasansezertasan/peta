"""The internal seam between enrichment orchestration and concrete sources.

A provider answers exactly one :data:`Capability` for one package and reports
the outcome as a :class:`ProviderResult`, so orchestration never needs to know
which HTTP service produced the evidence, how it failed, or how it is
configured.

This seam is deliberately internal. It is not a third-party plugin API, and it
carries no compatibility guarantees outside this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, TypeAliasType

from peta.core.models import VULNERABILITY_FIELD

if TYPE_CHECKING:
    from peta.core.models import PackageInfo, Vulnerability
    from peta.core.output import SourceState

__all__ = [
    "CAPABILITY_FIELDS",
    "Capability",
    "CountEvidence",
    "EnrichmentProvider",
    "Evidence",
    "ProviderGroup",
    "ProviderResult",
    "VulnerabilityEvidence",
]


# ``TypeAliasType`` (not a bare PEP 695 ``type`` statement) so the alias stays a
# runtime object the docs build and CodeQL can both resolve, matching how
# ``peta.core.output`` declares its contract aliases.
Capability = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "Capability", Literal["vulnerabilities", "download_count", "dependent_count"]
)
"""The single ``result`` field a provider contributes evidence for."""

ProviderGroup = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "ProviderGroup", Literal["vulnerabilities", "stats"]
)
"""The ``--no-osv`` / ``--no-stats`` family a provider belongs to.

Grouping lives on the provider so orchestration can honour the CLI's opt-out
flags without naming individual sources.
"""

CAPABILITY_FIELDS: dict[Capability, str] = {
    "vulnerabilities": VULNERABILITY_FIELD,
    "download_count": "result.download_count",
    "dependent_count": "result.dependent_count",
}
"""The output-contract ``fields`` path each capability writes to."""


@dataclass(frozen=True)
class VulnerabilityEvidence:
    """Advisories a provider found for the subject."""

    vulnerabilities: list[Vulnerability]

    @property
    def is_empty(self) -> bool:
        """Whether the source confirmed it has no advisories.

        Returns:
            ``True`` when no advisories were returned.
        """
        return not self.vulnerabilities


@dataclass(frozen=True)
class CountEvidence:
    """A single scalar count, such as downloads or dependents."""

    count: int

    @property
    def is_empty(self) -> bool:
        """Whether this counts as no answer.

        Always ``False``: a count of zero is a real value, and a source with
        no count to give returns no evidence at all.

        Returns:
            ``False``.
        """
        return False


Evidence = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "Evidence", "VulnerabilityEvidence | CountEvidence"
)
"""Typed payload a provider returns, carried separately from its provenance."""


_EVIDENCE_TYPES: dict[Capability, type[VulnerabilityEvidence | CountEvidence]] = {
    "vulnerabilities": VulnerabilityEvidence,
    "download_count": CountEvidence,
    "dependent_count": CountEvidence,
}
"""The evidence variant each capability must carry."""

_EVIDENCE_FREE_STATES = frozenset({"failed", "skipped", "unavailable"})
"""States that describe an absent answer, so cannot carry evidence."""


def _validate_state(state: SourceState, evidence: Evidence | None) -> None:
    """Require the state and the evidence to describe the same outcome.

    Exactly one state means "here is an answer". Every other state describes an
    absent one, so carrying a real answer under it contradicts the provenance
    the record will produce.

    Raises:
        ValueError: If the state and the evidence disagree.
    """
    answered = evidence is not None and not evidence.is_empty
    if answered != (state == "success"):
        detail = (
            f"state {state!r} cannot carry an answer"
            if answered
            else "state 'success' must carry a non-empty answer"
        )
        raise ValueError(detail)
    if evidence is not None and state in _EVIDENCE_FREE_STATES:
        msg = f"state {state!r} cannot carry evidence"
        raise ValueError(msg)


def _validate_capability(capability: Capability, evidence: Evidence | None) -> None:
    """Require the evidence variant to match the capability it answers.

    Raises:
        TypeError: If the evidence variant does not match the capability.
    """
    # Identity, not ``isinstance``: the evidence union covers both variants, so
    # a subtype check narrows to "always true" and hides the mismatch.
    if evidence is not None and type(evidence) is not _EVIDENCE_TYPES[capability]:
        msg = f"{type(evidence).__name__} does not match capability {capability!r}"
        raise TypeError(msg)


@dataclass(frozen=True)
class ProviderResult:
    """One provider's answer for one package, evidence and provenance together.

    ``state`` reuses the output contract's :data:`~peta.core.output.SourceState`
    so a result maps onto a source record without a translation table.
    """

    provider: str
    capability: Capability
    state: SourceState
    subject: str
    retrieved_at: str | None = None
    evidence: Evidence | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        """Reject result variants that orchestration could not merge coherently.

        ``capability``, ``state``, and ``evidence`` are typed independently, so
        nothing else stops an adapter from pairing ``CountEvidence`` with the
        ``vulnerabilities`` capability, attaching evidence to a failure, or
        claiming a source returned nothing while carrying an answer. Each would
        write one thing while claiming another in provenance, so they are
        rejected where they are constructed rather than merged silently.

        The checks live in :func:`_validate_state` and
        :func:`_validate_capability`, which raise on a contradiction.
        """
        _validate_state(self.state, self.evidence)
        _validate_capability(self.capability, self.evidence)

    @property
    def field(self) -> str:
        """Name the ``result`` path this provider contributes to.

        Returns:
            The output-contract field path for the provider's capability.
        """
        return CAPABILITY_FIELDS[self.capability]


class EnrichmentProvider(Protocol):
    """An optional metadata source that enriches one package.

    Implementations expose their identity as ``name``, the single result field
    they contribute as ``capability``, and their opt-out family as ``group``.

    Implementations must not raise: every outcome, including failure and
    missing configuration, is reported as a :class:`ProviderResult` so one
    source can never abort another.

    The member bodies below raise rather than using a bare ``...``: a protocol
    body is never executed, and an explicit raise says so without leaving a
    statement that has no effect.
    """

    @property
    def name(self) -> str:
        """Identify the source in provenance and warnings.

        Returns:
            The provider's stable source name.

        Raises:
            NotImplementedError: Always; implementations supply the value.
        """
        raise NotImplementedError

    @property
    def capability(self) -> Capability:
        """Name the single result field this provider contributes.

        Returns:
            The provider's capability.

        Raises:
            NotImplementedError: Always; implementations supply the value.
        """
        raise NotImplementedError

    @property
    def group(self) -> ProviderGroup:
        """Name the opt-out family this provider belongs to.

        Returns:
            The provider's group.

        Raises:
            NotImplementedError: Always; implementations supply the value.
        """
        raise NotImplementedError

    def fetch(self, pkg: PackageInfo) -> ProviderResult:
        """Look up this provider's capability for ``pkg``.

        Args:
            pkg: The resolved package to look up.

        Returns:
            The outcome, whether evidence, an empty answer, or a failure.

        Raises:
            NotImplementedError: Always; implementations perform the lookup.
        """
        raise NotImplementedError
