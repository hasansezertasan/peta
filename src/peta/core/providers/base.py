"""The internal seam between enrichment orchestration and concrete sources.

A provider answers exactly one :data:`Capability` for one package and reports
the outcome as a :class:`ProviderResult`, so orchestration never needs to know
which HTTP service produced the evidence, how it failed, or how it is
configured.

This seam is deliberately internal. It is not a third-party plugin API, and it
carries no compatibility guarantees outside this package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol, TypeAliasType, cast

from peta.core.cache import FRESHNESS_VALUES
from peta.core.models import VULNERABILITY_FIELD, ProviderWarning, Vulnerability
from peta.core.output import SOURCE_STATES

if TYPE_CHECKING:
    from peta.core.cache import Freshness
    from peta.core.models import PackageInfo
    from peta.core.output import SourceState

__all__ = [
    "CAPABILITY_FIELDS",
    "CAPABILITY_GROUPS",
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
"""The ``--no-osv`` / ``--no-stats`` family a capability belongs to."""

CAPABILITY_GROUPS: dict[Capability, ProviderGroup] = {
    "vulnerabilities": "vulnerabilities",
    "download_count": "stats",
    "dependent_count": "stats",
}
"""The opt-out family each capability falls under.

Derived from the capability rather than declared per provider: the CLI's
opt-out flags select kinds of data, so a provider cannot place itself in a
group that does not match what it supplies and thereby escape its own flag.
"""

CAPABILITY_FIELDS: dict[Capability, str] = {
    "vulnerabilities": VULNERABILITY_FIELD,
    "download_count": "result.download_count",
    "dependent_count": "result.dependent_count",
}
"""The output-contract ``fields`` path each capability writes to."""


def _is_vulnerability(item: object) -> bool:
    """Check an untrusted list item against the payload's declared element type.

    Takes ``object`` rather than ``Vulnerability`` so the check is a real
    narrowing for the type checkers, not a statically-redundant one: an
    injected provider can pass anything at runtime regardless of what the
    caller's list is annotated to hold.

    Returns:
        ``True`` if ``item`` is a genuine :class:`Vulnerability`.
    """
    return isinstance(item, Vulnerability)


@dataclass(frozen=True)
class VulnerabilityEvidence:
    """Advisories a provider found for the subject."""

    vulnerabilities: list[Vulnerability]

    def __post_init__(self) -> None:
        """Reject a payload the merge could not read safely.

        Checks both the outer type and the fields
        :func:`peta.core.vulns._identity` hashes (``id`` and ``aliases``),
        since a genuine ``Vulnerability`` whose ``id`` or alias is unhashable
        would crash the set construction outside ``_consult``'s guard.

        Raises:
            TypeError: If any item is not a well-formed
                :class:`~peta.core.models.Vulnerability`.
        """
        for item in self.vulnerabilities:
            if not _is_vulnerability(item):
                msg = "vulnerabilities must contain only Vulnerability instances"
                raise TypeError(msg)
            if not isinstance(cast("object", item.id), str) or not all(
                isinstance(cast("object", a), str) for a in item.aliases
            ):
                msg = "vulnerability id and aliases must be strings"
                raise TypeError(msg)

    @property
    def is_empty(self) -> bool:
        """Whether the source confirmed it has no advisories.

        Returns:
            ``True`` when no advisories were returned.
        """
        return not self.vulnerabilities


def _is_count(value: object) -> bool:
    """Check an untrusted scalar against the payload's declared element type.

    Takes ``object`` rather than ``int`` for the same reason as
    :func:`_is_vulnerability`: an injected provider can pass anything at
    runtime regardless of the field's annotation. ``bool`` is rejected too,
    matching :func:`peta.core.validation.expect_int`, since ``isinstance(True,
    int)`` is ``True`` but a JSON boolean is not a genuine count.

    Returns:
        ``True`` if ``value`` is a genuine, non-boolean ``int``.
    """
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class CountEvidence:
    """A single scalar count, such as downloads or dependents."""

    count: int

    def __post_init__(self) -> None:
        """Reject a count that would corrupt ``PackageInfo`` and its output.

        The ``int`` annotation is only a static promise: an injected provider
        can satisfy it at the type-checker level while returning anything at
        runtime. Left unchecked, a malformed count flows straight onto
        :attr:`~peta.core.models.PackageInfo.download_count` or
        ``dependent_count`` and only fails later, such as at ``f"{count:,}"``
        formatting in the table renderer, well outside the guard that
        contains a normal provider failure.

        Raises:
            TypeError: If ``count`` is not a genuine, non-boolean ``int``.
        """
        if not _is_count(self.count):
            msg = "count must be a non-boolean int"
            raise TypeError(msg)

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
    "Evidence", VulnerabilityEvidence | CountEvidence
)
"""Typed payload a provider returns, carried separately from its provenance."""


_EVIDENCE_TYPES: dict[Capability, type[VulnerabilityEvidence | CountEvidence]] = {
    "vulnerabilities": VulnerabilityEvidence,
    "download_count": CountEvidence,
    "dependent_count": CountEvidence,
}
"""The evidence variant each capability must carry."""

_EVIDENCE_FREE_STATES = frozenset({"failed", "skipped", "unavailable", "unsupported"})
"""States that describe an absent answer, so cannot carry evidence."""


def _validate_state(state: SourceState, evidence: Evidence | None) -> None:
    """Require the state and the evidence to describe the same outcome.

    Exactly one state means "here is an answer". Every other state describes an
    absent one, so carrying a real answer under it contradicts the provenance
    the record will produce.

    Raises:
        ValueError: If the state is not a documented one, or the state and the
            evidence disagree.
    """
    if state not in SOURCE_STATES:
        # An injected provider can supply any string despite the annotation,
        # and an undocumented state would reach the envelope unchallenged.
        msg = f"state {state!r} is not a documented source state"
        raise ValueError(msg)
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


def _validate_reason(state: SourceState, reason: str | None) -> None:
    """Require a failure to explain itself.

    A provider failure is deliberately non-fatal, so the warning built from
    this reason is the only account the user gets of the missing data. An
    empty one would report that something went wrong and nothing else.

    Raises:
        ValueError: If a failed result carries no diagnostic.
    """
    if state in {"failed", "unsupported"} and not (reason or "").strip():
        msg = f"state {state!r} must carry a reason"
        raise ValueError(msg)


def _validate_capability(capability: Capability, evidence: Evidence | None) -> None:
    """Require the evidence variant to match the capability it answers.

    Raises:
        TypeError: If the evidence variant does not match the capability.
    """
    if evidence is None:
        return
    expected = _EVIDENCE_TYPES.get(capability)
    # Identity, not ``isinstance``: the evidence union covers both variants, so
    # a subtype check narrows to "always true" and hides the mismatch.
    if expected is None or type(evidence) is not expected:
        msg = f"{type(evidence).__name__} does not match capability {capability!r}"
        raise TypeError(msg)


def _validate_freshness(freshness: Freshness | None) -> None:
    """Require a stated origin to be one the output contract documents.

    Checked for the same reason as ``state``: the annotation is only a static
    promise, and an injected provider can put any string here, which would
    reach the envelope as an undocumented value.

    Raises:
        ValueError: If the value is not a documented freshness.
    """
    if freshness is not None and freshness not in FRESHNESS_VALUES:
        msg = f"freshness {freshness!r} is not a documented origin"
        raise ValueError(msg)


def _validate_warnings(warnings: list[ProviderWarning]) -> None:
    """Require warnings to be a list of well-formed ``ProviderWarning`` items.

    Raises:
        TypeError: If ``warnings`` is not iterable or contains a non-warning.
    """
    if not isinstance(cast("object", warnings), list):
        msg = f"warnings must be a list, got {type(warnings).__name__}"
        raise TypeError(msg)
    for item in warnings:
        if not isinstance(cast("object", item), ProviderWarning):
            msg = "warnings must contain only ProviderWarning instances"
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
    freshness: Freshness | None = None
    upstream_id: str | None = None
    evidence: Evidence | None = None
    reason: str | None = None
    warnings: list[ProviderWarning] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Reject result variants that orchestration could not merge coherently.

        ``capability``, ``state``, and ``evidence`` are typed independently, so
        nothing else stops an adapter from pairing ``CountEvidence`` with the
        ``vulnerabilities`` capability, attaching evidence to a failure, or
        claiming a source returned nothing while carrying an answer. Each would
        write one thing while claiming another in provenance, so they are
        rejected where they are constructed rather than merged silently.

        The checks live in :func:`_validate_state`, :func:`_validate_reason`,
        and :func:`_validate_capability`, which raise on a contradiction.
        """
        _validate_state(self.state, self.evidence)
        _validate_reason(self.state, self.reason)
        _validate_capability(self.capability, self.evidence)
        _validate_freshness(self.freshness)
        _validate_warnings(self.warnings)

    @property
    def field(self) -> str | None:
        """Name the ``result`` path this provider contributes to.

        ``None`` when the capability is not one peta knows, which an injected
        provider can declare at runtime despite the annotation. Such a result
        has no attributable field rather than an invented one.

        Returns:
            The output-contract field path, or ``None`` if unattributable.
        """
        return CAPABILITY_FIELDS.get(self.capability)


class EnrichmentProvider(Protocol):
    """An optional metadata source that enriches one package.

    Implementations expose their identity as ``name`` and the single result
    field they contribute as ``capability``; the opt-out family follows from
    the capability via :data:`CAPABILITY_GROUPS`.

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
