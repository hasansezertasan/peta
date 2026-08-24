"""OSV.dev vulnerability lookups (best-effort enrichment)."""

from __future__ import annotations

from typing import Required, TypedDict, cast

import httpx

from peta.core.models import Vulnerability
from peta.core.remote import DEFAULT_TIMEOUT

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

# Best-effort errors swallowed to ``[]`` (network, or a malformed/partial body).
# Kept as a named tuple so ``ruff format`` cannot rewrite a parenthesized
# ``except (...)`` into invalid ``except A, B:`` syntax.
_BEST_EFFORT_ERRORS = (
    httpx.RequestError,
    AttributeError,
    KeyError,
    TypeError,
    ValueError,
)


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
    response = httpx.post(
        OSV_API_URL, json=_query_body(name, version), timeout=DEFAULT_TIMEOUT
    )
    if response.status_code != 200:  # ruff: ignore[magic-value-comparison]
        msg = f"OSV returned HTTP {response.status_code}"
        raise ValueError(msg)
    return cast("OsvResponse", response.json())


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
        aliases=vuln.get("aliases", []),
        summary=vuln.get("summary") or vuln.get("details") or "",
        fixed_in=_fixed_versions(vuln.get("affected", [])),
        severity=_severity(vuln.get("severity", [])),
    )


def get_vulnerabilities(name: str, version: str | None = None) -> list[Vulnerability]:
    """Look up known vulnerabilities for a package on OSV.dev.

    This is best-effort enrichment: any network failure, non-200 response,
    or malformed body results in an empty list rather than raising.

    Args:
        name: Package name to query (assumed to be a PyPI package).
        version: Optional specific version; if ``None`` all versions are queried.

    Returns:
        The list of vulnerabilities reported by OSV, or ``[]`` on any failure.
    """
    try:
        data = _fetch(name, version)
        return [_to_vulnerability(v) for v in data.get("vulns", [])]
    except _BEST_EFFORT_ERRORS:
        return []
