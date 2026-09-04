"""OSV.dev vulnerability lookups (best-effort enrichment)."""

from __future__ import annotations

from typing import Required, TypedDict, cast

import httpx

from peta.core.models import Vulnerability
from peta.core.remote import DEFAULT_TIMEOUT
from peta.core.validation import (
    EnrichmentError,
    ResponseValidationError,
    expect_list,
    expect_mapping,
    expect_string,
    optional_string,
    optional_string_list,
)

__all__ = [
    "OSV_API_URL",
    "OsvAffected",
    "OsvEvent",
    "OsvRange",
    "OsvResponse",
    "OsvSeverity",
    "OsvVuln",
    "get_vulnerabilities",
]


OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_SOURCE = "osv"


# The OSV API is untyped from Python's perspective (``response.json()``
# returns ``Any``). These ``TypedDict``\ s describe only the fields peta
# reads, so the decoded body can be brought into the typed world with a
# single ``typing.cast`` at the ``.json()`` boundary.
class OsvEvent(TypedDict, total=False):
    """A single event within an affected range (only ``fixed`` is read)."""

    fixed: str


class OsvRange(TypedDict, total=False):
    """A range of affected versions."""

    events: list[OsvEvent]


class OsvAffected(TypedDict, total=False):
    """A single ``affected`` entry of an OSV vulnerability."""

    ranges: list[OsvRange]


class OsvSeverity(TypedDict, total=False):
    """A single ``severity`` entry of an OSV vulnerability (only ``score`` is read)."""

    score: str


class OsvVuln(TypedDict, total=False):
    """A single entry of the ``vulns`` array."""

    id: Required[str]
    aliases: list[str]
    summary: str
    details: str
    affected: list[OsvAffected]
    severity: list[OsvSeverity]


class OsvResponse(TypedDict, total=False):
    """The top-level OSV JSON payload for a query."""

    vulns: list[OsvVuln]


def _query_body(name: str, version: str | None) -> dict[str, object]:
    body: dict[str, object] = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version is not None:
        body["version"] = version
    return body


def _fetch(name: str, version: str | None) -> OsvResponse:
    try:
        response = httpx.post(
            OSV_API_URL, json=_query_body(name, version), timeout=DEFAULT_TIMEOUT
        )
    except httpx.RequestError as exc:
        raise EnrichmentError(OSV_SOURCE, str(exc)) from exc
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        raise EnrichmentError(OSV_SOURCE, f"HTTP {response.status_code}")
    try:
        body = cast("object", response.json())
    except ValueError as exc:
        raise EnrichmentError(OSV_SOURCE, "invalid JSON") from exc
    try:
        return _validate_response(body)
    except ResponseValidationError as exc:
        raise EnrichmentError(OSV_SOURCE, f"malformed response: {exc}") from exc


def _validate_event(value: object, path: str) -> None:
    event = expect_mapping(value, source="OSV", path=path)
    _ = optional_string(event, "fixed", source="OSV", path=path)


def _validate_range(value: object, path: str) -> None:
    affected_range = expect_mapping(value, source="OSV", path=path)
    events = expect_list(
        affected_range.get("events", []), source="OSV", path=f"{path}.events"
    )
    for index, event in enumerate(events):
        _validate_event(event, f"{path}.events[{index}]")


def _validate_affected(value: object, path: str) -> None:
    affected = expect_mapping(value, source="OSV", path=path)
    ranges = expect_list(
        affected.get("ranges", []), source="OSV", path=f"{path}.ranges"
    )
    for index, affected_range in enumerate(ranges):
        _validate_range(affected_range, f"{path}.ranges[{index}]")


def _validate_severity(value: object, path: str) -> None:
    severity = expect_mapping(value, source="OSV", path=path)
    _ = optional_string(severity, "score", source="OSV", path=path)


def _validate_vulnerability(value: object, path: str) -> None:
    vuln = expect_mapping(value, source="OSV", path=path)
    _ = expect_string(vuln.get("id"), source="OSV", path=f"{path}.id")
    _ = optional_string(vuln, "summary", source="OSV", path=path)
    _ = optional_string(vuln, "details", source="OSV", path=path)
    _ = optional_string_list(vuln, "aliases", source="OSV", path=path)
    affected = expect_list(
        vuln.get("affected", []), source="OSV", path=f"{path}.affected"
    )
    for index, item in enumerate(affected):
        _validate_affected(item, f"{path}.affected[{index}]")
    severity = expect_list(
        vuln.get("severity", []), source="OSV", path=f"{path}.severity"
    )
    for index, item in enumerate(severity):
        _validate_severity(item, f"{path}.severity[{index}]")


def _validate_response(body: object) -> OsvResponse:
    root = expect_mapping(body, source="OSV", path="$")
    vulnerabilities = expect_list(root.get("vulns", []), source="OSV", path="$.vulns")
    for index, vulnerability in enumerate(vulnerabilities):
        _validate_vulnerability(vulnerability, f"$.vulns[{index}]")
    return cast("OsvResponse", cast("object", root))


def _fixed_versions(affected: list[OsvAffected]) -> list[str]:
    fixed: list[str] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            for event in rng.get("events", []):
                version = event.get("fixed")
                if version and version not in fixed:
                    fixed.append(version)
    return fixed


def _severity(raw: list[OsvSeverity]) -> str | None:
    if not raw:
        return None
    return raw[0].get("score")


def _to_vulnerability(vuln: OsvVuln) -> Vulnerability:
    return Vulnerability(
        id=vuln["id"],
        aliases=vuln.get("aliases") or [],
        summary=vuln.get("summary") or vuln.get("details") or "",
        fixed_in=_fixed_versions(vuln.get("affected", [])),
        severity=_severity(vuln.get("severity", [])),
    )


def get_vulnerabilities(name: str, version: str | None = None) -> list[Vulnerability]:
    """Look up known vulnerabilities for a package on OSV.dev.

    The caller may treat this as best-effort by catching
    :class:`~peta.core.validation.EnrichmentError` and retaining its source and
    reason.

    Args:
        name: Package name to query (assumed to be a PyPI package).
        version: Optional specific version; if ``None`` all versions are queried.

    Returns:
        The list of vulnerabilities reported by OSV.

    """
    data = _fetch(name, version)
    return [_to_vulnerability(v) for v in data.get("vulns", [])]
