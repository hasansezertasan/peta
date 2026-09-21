"""Typed models for peta's versioned output contract."""

from __future__ import annotations

import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, TypeAliasType, cast

from packaging.markers import default_environment

from peta._version import __version__

if TYPE_CHECKING:
    from collections.abc import Mapping

    from peta.core.cache import Freshness

__all__ = [
    "SCHEMA_VERSION",
    "SOURCE_STATES",
    "TARGET_ENVIRONMENT_KEY",
    "CommandName",
    "EnvelopeStatus",
    "MessageCode",
    "OutputEnvelope",
    "OutputMessage",
    "OutputQuery",
    "SourceRecord",
    "SourceState",
    "TargetEnvironment",
    "make_envelope",
    "utc_from",
    "utc_now",
]

SCHEMA_VERSION = "1"

TARGET_ENVIRONMENT_KEY = "target_environment"
"""How a command hands :func:`make_envelope` its resolved target.

Transport only. It travels in the ``arguments`` mapping because that is the
one channel every command already threads through to the envelope, and
:func:`make_envelope` removes it again before serialization: ``arguments`` is
the contract's record of the CLI invocation, so publishing the environment
there as well would both duplicate ``query.target_environment`` and put an
undocumented nested object in front of exact consumers.
"""
# CodeQL does not yet recognize PEP 695 ``type`` statements as definitions when
# checking ``__all__``. Keep these runtime-visible assignments until it does.
CommandName = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "CommandName", Literal["info", "compare", "deps", "files", "versions", "artifacts"]
)
EnvelopeStatus = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "EnvelopeStatus", Literal["success", "partial", "empty", "failed"]
)
MessageCode = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "MessageCode",
    Literal[
        "dependency_not_found",
        "dependency_depth_limited",
        "dependency_resolution_failed",
        "dependency_target_incompatible",
        "dependency_version_conflict",
        "enrichment_failed",
        "invalid_arguments",
        "network_error",
        "offline_unavailable",
        "package_not_found",
        "provider_conflict",
        "provider_warning",
    ],
)
SourceState = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "SourceState",
    Literal["success", "empty", "skipped", "unavailable", "unsupported", "failed"],
)

SOURCE_STATES: frozenset[SourceState] = frozenset({
    "success",
    "empty",
    "skipped",
    "unavailable",
    "unsupported",
    "failed",
})
"""Every documented source state, as a runtime-checkable set.

Lets a runtime-supplied state be checked against the schema before it reaches
the envelope, since an annotation alone does not stop one. Kept in step with
:data:`SourceState` by ``test_source_states_match_the_alias``.
"""


@dataclass(frozen=True)
class TargetEnvironment:
    """Interpreter and platform used to evaluate the query."""

    implementation: str
    python_version: str
    platform: str
    interpreter: str | None = None
    paths: tuple[str, ...] = ()
    markers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def current(cls) -> TargetEnvironment:
        """Describe the current runtime.

        ``markers`` is populated even though no target was named: an
        untargeted run still evaluates dependency markers against the running
        interpreter, and leaving the field empty would hide from consumers
        which values actually decided what the result contains.

        Returns:
            The active interpreter and operating-system platform.
        """
        return cls(
            implementation=platform.python_implementation(),
            python_version=platform.python_version(),
            platform=sys.platform,
            markers={key: str(value) for key, value in default_environment().items()},
        )


@dataclass(frozen=True)
class OutputQuery:
    """The command invocation represented by an output envelope."""

    command: CommandName
    arguments: dict[str, object]
    target_environment: TargetEnvironment


@dataclass(frozen=True)
class OutputMessage:
    """A structured warning or error."""

    code: MessageCode
    message: str
    source: str | None = None


@dataclass(frozen=True)
class SourceRecord:
    """Retrieval state for one metadata source."""

    name: str
    state: SourceState
    target: str | None = None
    retrieved_at: str | None = None
    reason: str | None = None
    freshness: Freshness | None = None
    """Whether this record's data came from the source or from peta's cache.

    Absent when the question does not apply — a source read from the local
    environment, or one that never completed a retrieval.
    """
    fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OutputEnvelope:
    """Stable top-level shape for machine-readable output."""

    query: OutputQuery
    status: EnvelopeStatus
    result: object
    generated_at: str
    sources: list[SourceRecord] = field(default_factory=list)
    warnings: list[OutputMessage] = field(default_factory=list)
    errors: list[OutputMessage] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    peta_version: str = __version__

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping without absent optional fields.

        Returns:
            The serialized contract mapping.
        """
        environment = self.query.target_environment
        query = {
            "command": self.query.command,
            "arguments": self.query.arguments,
            "target_environment": {
                "implementation": environment.implementation,
                "python_version": environment.python_version,
                "platform": environment.platform,
                "interpreter": environment.interpreter,
                "paths": list(environment.paths),
                "markers": environment.markers,
            },
        }
        return {
            "schema_version": self.schema_version,
            "peta_version": self.peta_version,
            "generated_at": self.generated_at,
            "query": query,
            "status": self.status,
            "sources": [_without_none(asdict(item)) for item in self.sources],
            "warnings": [_without_none(asdict(item)) for item in self.warnings],
            "errors": [_without_none(asdict(item)) for item in self.errors],
            "result": self.result,
        }


def _without_none(data: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in data.items() if value is not None}


def _rfc3339(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_now() -> str:
    """Return the current UTC time in RFC 3339 form.

    Returns:
        A second-precision UTC timestamp ending in ``Z``.
    """
    return _rfc3339(datetime.now(UTC))


def utc_from(timestamp: float) -> str:
    """Format a Unix timestamp in the same RFC 3339 form as :func:`utc_now`.

    Lets a response served from cache report when it was actually retrieved
    rather than when it was replayed.

    Args:
        timestamp: Seconds since the epoch.

    Returns:
        A second-precision UTC timestamp ending in ``Z``.
    """
    return _rfc3339(datetime.fromtimestamp(timestamp, UTC))


def make_envelope(
    command: CommandName,
    *,
    arguments: dict[str, object] | None,
    status: EnvelopeStatus,
    result: object,
    sources: list[SourceRecord] | None = None,
    warnings: list[OutputMessage] | None = None,
    errors: list[OutputMessage] | None = None,
    generated_at: str | None = None,
) -> OutputEnvelope:
    """Build an output envelope using the current runtime as the target.

    Returns:
        A populated, typed output envelope.
    """
    supplied = (arguments or {}).get(TARGET_ENVIRONMENT_KEY)
    # Stripped rather than passed through: see TARGET_ENVIRONMENT_KEY.
    recorded = {
        key: value
        for key, value in (arguments or {}).items()
        if key != TARGET_ENVIRONMENT_KEY
    }
    target = TargetEnvironment.current()
    if isinstance(supplied, dict):
        supplied = cast("dict[str, object]", supplied)
        target = TargetEnvironment(
            implementation=str(supplied["implementation"]),
            python_version=str(supplied["python_version"]),
            platform=str(supplied["platform"]),
            interpreter=cast("str | None", supplied.get("interpreter")),
            paths=tuple(cast("list[str]", supplied.get("paths", []))),
            markers=cast("dict[str, str]", supplied.get("markers", {})),
        )
    return OutputEnvelope(
        query=OutputQuery(
            command=command, arguments=recorded, target_environment=target
        ),
        status=status,
        result=result,
        generated_at=generated_at or utc_now(),
        sources=sources or [],
        warnings=warnings or [],
        errors=errors or [],
    )
