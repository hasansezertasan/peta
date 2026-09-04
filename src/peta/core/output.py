"""Typed models for peta's versioned output contract."""

from __future__ import annotations

import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, TypeAliasType

from peta._version import __version__

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "SCHEMA_VERSION",
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
    "utc_now",
]

SCHEMA_VERSION = "1"
# CodeQL does not yet recognize PEP 695 ``type`` statements as definitions when
# checking ``__all__``. Keep these runtime-visible assignments until it does.
CommandName = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "CommandName", Literal["info", "compare", "deps", "files", "versions"]
)
EnvelopeStatus = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "EnvelopeStatus", Literal["success", "partial", "empty", "failed"]
)
MessageCode = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "MessageCode",
    Literal[
        "dependency_not_found",
        "dependency_resolution_failed",
        "enrichment_failed",
        "invalid_arguments",
        "network_error",
        "package_not_found",
    ],
)
SourceState = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "SourceState", Literal["success", "empty", "skipped", "unavailable", "failed"]
)


@dataclass(frozen=True)
class TargetEnvironment:
    """Interpreter and platform used to evaluate the query."""

    implementation: str
    python_version: str
    platform: str

    @classmethod
    def current(cls) -> TargetEnvironment:
        """Describe the current runtime.

        Returns:
            The active interpreter and operating-system platform.
        """
        return cls(
            implementation=platform.python_implementation(),
            python_version=platform.python_version(),
            platform=sys.platform,
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


def utc_now() -> str:
    """Return the current UTC time in RFC 3339 form.

    Returns:
        A second-precision UTC timestamp ending in ``Z``.
    """
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    return OutputEnvelope(
        query=OutputQuery(
            command=command,
            arguments=arguments or {},
            target_environment=TargetEnvironment.current(),
        ),
        status=status,
        result=result,
        generated_at=generated_at or utc_now(),
        sources=sources or [],
        warnings=warnings or [],
        errors=errors or [],
    )
