"""On-disk cache for successful responses, and the settings that govern it.

Peta re-asks the same questions constantly: a dependency tree resolves the same
transitive packages, and a pinned release's metadata cannot change once it is
published. Caching those answers turns a repeat query into a local read, and
makes working without a network possible rather than merely degraded.

Only ``200`` responses are stored. An error is a fact about right now, not
about the package, so caching one would turn a transient outage into a
persistent wrong answer.

How long an entry stays usable is the caller's decision, not this module's:
the code building a URL is the only code that knows what kind of answer it
asked for. This module supplies the vocabulary — :data:`LATEST`, :data:`DAILY`
— and each source picks from it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeAliasType, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

__all__ = [
    "DAILY",
    "FRESHNESS_VALUES",
    "LATEST",
    "MAX_AGE",
    "CacheSettings",
    "CachedResponse",
    "Freshness",
    "Provenance",
    "configure",
    "default_directory",
    "entries_directory",
    "key_for",
    "load",
    "now",
    "redacted",
    "reset",
    "settings",
    "store",
]


Freshness = TypeAliasType(  # ruff: ignore[non-pep695-type-alias]
    "Freshness", Literal["live", "cached", "revalidated"]
)
"""Where a response came from.

``live`` means the source answered, ``cached`` means the entry was read from
disk without contacting the source, and ``revalidated`` means the source
confirmed a stored entry was still current without resending its body.
"""

FRESHNESS_VALUES: frozenset[Freshness] = frozenset({"live", "cached", "revalidated"})
"""Every documented freshness value, as a runtime-checkable set.

Kept in step with :data:`Freshness` by ``test_freshness_values_match_the_alias``.
"""

LATEST = 60 * 60
"""A package's metadata response, whether a version was pinned or not.

It is tempting to keep a pinned release for far longer, since its metadata is
settled once published. The *response* is not: PyPI's package payload also
carries a ``vulnerabilities`` array, and advisories are published against
releases long after they ship. A month-long entry would let ``info
name==version --no-osv`` report a package as clear after PyPI had already
published an advisory against it, so the whole response expires on the
advisory data's schedule rather than the metadata's.
"""

DAILY = 6 * 60 * 60
"""Download and dependent counts are recomputed about once a day.

Shorter than a day so a query late in the cycle does not serve a count from
two refreshes ago.
"""

MAX_AGE = 30 * 24 * 60 * 60
"""How long any entry may sit on disk, however long its TTL.

A TTL decides whether an entry may still be *served*; without a separate
bound nothing would ever delete one, so querying many packages — a dependency
tree especially — would leave every file behind for good. Comfortably longer
than any TTL, so pruning never discards an entry that could still have been
served, and short enough that an abandoned cache does not grow without limit.
"""

_CREDENTIAL_PARAMS = frozenset({
    "access_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "secret",
    "token",
})
"""Query parameters redacted before a URL is hashed, stored, or reported.

Libraries.io takes its API key in the query string, so the URL peta requests
contains a credential. It must never reach the cache — neither in a file name
derived from it nor in the stored entry — because the cache outlives the
process and is world-readable in the user's home directory.

Redacting rather than including is also correct for the key: the response
depends on which package was asked about, not on who asked, so two users with
different keys should share one entry.
"""

_STORED_HEADERS = frozenset({"content-type", "etag", "last-modified"})
"""Response headers worth keeping, as an allowlist rather than a denylist.

Storing whole header sets would persist whatever a source chose to send —
cookies, rate-limit tokens, anything added later. Only validators and the
content type are needed to serve or revalidate an entry.
"""

_UNDATABLE = (OSError, OverflowError, ValueError)
"""Every way a stored timestamp can fail to convert into a date.

A tuple constant for the same reason as :data:`_UNREADABLE`: the formatter
strips inline ``except (A, B)`` parentheses into the bare form PEP 758
permits, which Python 3.14 accepts but some of the project's other tools
cannot yet parse.
"""

_UNREADABLE = (OSError, ValueError)
"""Every way reading an entry can fail: absent, unopenable, or not JSON.

A tuple constant rather than an inline ``except (OSError, ValueError)``,
matching the convention elsewhere in this package: the formatter strips those
parentheses into the bare form PEP 758 permits, which Python 3.14 accepts but
some of the project's other tools cannot yet parse.
"""

_ENTRY_DIR = "entries"
"""Subdirectory of the configured location that holds the entries.

Peta writes and prunes only inside this, never in the directory it was
pointed at. A name pattern alone is not proof of ownership: a shared
content-addressed directory can hold foreign files named exactly like a
SHA-256 digest, and pruning by name would delete them. Owning a subdirectory
means nothing peta did not create is ever a candidate.
"""

_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}\.json$")
"""Names :func:`key_for` can produce: a SHA-256 hex digest plus the suffix.

A second check on top of :data:`_ENTRY_DIR`, so anything a user drops into
peta's own subdirectory is still left alone.
"""

_PRUNED: list[bool] = []
"""Whether pruning has already run in this process.

Once is enough: entries expire by age, not during a single invocation, so
scanning again after every write would make a cold dependency tree do
quadratic filesystem work for no benefit.
"""

_SETTINGS: list[CacheSettings] = []
"""Holds the active settings, resolved once per process.

A list rather than a module-level ``None`` because rebinding a module global
needs a ``global`` statement, which this project's lint rules reject. Empty
means "not configured yet", which :func:`settings` reads as the defaults.
"""


def now() -> float:
    """Return the current wall-clock time as a Unix timestamp.

    Indirected through a function so tests can drive expiry from a fixed
    clock instead of sleeping.

    Returns:
        Seconds since the epoch.
    """
    return time.time()


def default_directory() -> Path:
    """Locate the cache directory for the current platform.

    Resolved by hand rather than through ``platformdirs``: it is four
    branches, and peta's runtime dependencies are deliberately few.

    Returns:
        The per-user cache directory for peta.
    """
    override = os.environ.get("PETA_CACHE_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "peta" / "Cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "peta"
    return Path.home() / ".cache" / "peta"


@dataclass(frozen=True)
class CacheSettings:
    """How the cache behaves for this invocation."""

    directory: Path
    offline: bool = False
    """Never contact a source; serve from cache or fail."""
    refresh: bool = False
    """Ignore stored entries and replace them with a fresh response."""
    enabled: bool = True
    """Whether to read or write the cache at all."""


def settings() -> CacheSettings:
    """Return the active settings, defaulting until :func:`configure` runs.

    Defaults apply so importing a source module and making a request works
    without the CLI having wired anything up, which is what the unit tests
    and any library use rely on.

    Returns:
        The active cache settings.
    """
    if not _SETTINGS:
        return CacheSettings(directory=default_directory())
    return _SETTINGS[0]


def configure(
    *,
    directory: Path | None = None,
    offline: bool = False,
    refresh: bool = False,
    enabled: bool = True,
) -> None:
    """Install the settings for this process.

    Held in module state rather than threaded through every signature: these
    are one decision made once at startup, and passing them down would mean
    adding parameters to every source, to the resolver, to the dependency
    walker, and to the provider protocol — all of which would then carry
    transport configuration they have no use for.

    Args:
        directory: Cache location; the platform default when ``None``.
        offline: Refuse to contact any source.
        refresh: Replace stored entries with fresh responses.
        enabled: Whether the cache is consulted at all.
    """
    _SETTINGS.clear()
    _PRUNED.clear()
    _SETTINGS.append(
        CacheSettings(
            directory=directory or default_directory(),
            offline=offline,
            refresh=refresh,
            enabled=enabled,
        )
    )


def reset() -> None:
    """Discard configured settings, restoring the defaults."""
    _SETTINGS.clear()
    _PRUNED.clear()


def redacted(url: str) -> str:
    """Rewrite a URL with credential-bearing query parameters removed.

    Public because the cache is not the only place a request URL is retained:
    an error that names the URL it could not answer would otherwise carry the
    credential into a message, a log, or a traceback.

    Args:
        url: A request URL, possibly carrying a credential.

    Returns:
        The URL with any parameter named in :data:`_CREDENTIAL_PARAMS` dropped.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (name, value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if name.lower() not in _CREDENTIAL_PARAMS
    ]
    return urlunsplit(parts._replace(query=urlencode(kept)))


def key_for(method: str, url: str, scope: str = "") -> str:
    """Derive the cache key for one request.

    ``scope`` separates consumers that fetch the same URL but validate
    different parts of it. Nothing is stored until its caller confirms the
    body was usable, and "usable" means usable *to that caller*: one command
    accepting a payload whose other half is malformed must not hand it to a
    command that reads that other half.

    Args:
        method: HTTP method, case-insensitive.
        url: The full request URL, credentials included; they are redacted
            before hashing.
        scope: Which consumer's view of the response this entry holds.

    Returns:
        A hex digest usable as a file name.
    """
    material = f"{method.upper()}\n{redacted(url)}\n{scope}"
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class Provenance:
    """Where a source's answer came from, and when it was retrieved.

    Carried separately from the answer so a caller can report accurate
    provenance without knowing whether the cache was involved. ``retrieved_at``
    is the moment the *source* answered, not the moment it was replayed: a
    response stored days ago and served from disk must not claim it was
    retrieved just now, or the provenance is worse than useless.
    """

    freshness: Freshness
    retrieved_at: str


@dataclass(frozen=True)
class CachedResponse:
    """A stored response and the moment it was stored."""

    status: int
    body: str
    headers: dict[str, str]
    stored_at: float

    def age(self, at: float) -> float:
        """Report how long ago this entry was stored.

        Args:
            at: The time to measure from.

        Returns:
            Age in seconds, never negative — a clock that moved backwards
            reads as brand new rather than as expired long ago.
        """
        return max(0.0, at - self.stored_at)

    def is_fresh(self, ttl: int, at: float) -> bool:
        """Whether this entry may still be served without asking the source.

        Args:
            ttl: How long entries of this kind stay usable, in seconds.
            at: The time to judge freshness at.

        Returns:
            ``True`` while the entry is within ``ttl``.
        """
        return self.age(at) < ttl

    @property
    def validators(self) -> dict[str, str]:
        """Conditional-request headers that would revalidate this entry.

        Returns:
            ``If-None-Match``/``If-Modified-Since`` headers, empty when the
            source supplied no validator to revalidate against.
        """
        headers: dict[str, str] = {}
        etag = self.headers.get("etag")
        if etag:
            headers["if-none-match"] = etag
        modified = self.headers.get("last-modified")
        if modified:
            headers["if-modified-since"] = modified
        return headers


def entries_directory() -> Path:
    """Locate the directory the entries themselves live in.

    Returns:
        The subdirectory of the configured location that peta owns.
    """
    return settings().directory / _ENTRY_DIR


def _path_for(key: str) -> Path:
    return entries_directory() / f"{key}.json"


def _is_string_map(value: object) -> bool:
    """Whether a decoded value is a mapping of strings to strings.

    Returns:
        ``True`` for a well-formed header mapping.
    """
    if not isinstance(value, dict):
        return False
    pairs = cast("dict[object, object]", value)
    return all(isinstance(k, str) and isinstance(v, str) for k, v in pairs.items())


def _is_representable(stored_at: float) -> bool:
    """Whether a timestamp can be turned back into a date.

    A finiteness test is not enough: ``1e999`` decodes to ``inf`` but ``1e20``
    is finite and still outside the range :func:`datetime.fromtimestamp`
    accepts. Either would read as forever fresh — the age clamps to zero — and
    then raise when the entry is dated for output, turning a damaged entry
    into a crash instead of the refetch the corruption path promises.

    Tested by conversion rather than against hardcoded bounds, so the check
    tracks whatever the platform actually supports.

    Returns:
        ``True`` if the timestamp is a usable date.
    """
    if not math.isfinite(stored_at):
        return False
    try:
        _ = datetime.fromtimestamp(stored_at, UTC)
    except _UNDATABLE:
        return False
    return True


def _is_entry_shape(status: object, body: object, stored_at: object) -> bool:
    """Whether the scalar fields of a decoded entry have usable types.

    ``bool`` is rejected as a status for the same reason
    :func:`peta.core.validation.expect_int` rejects it: ``isinstance(True,
    int)`` holds, but ``true`` is not a status code.

    Returns:
        ``True`` when every scalar field is of the expected type.
    """
    if not isinstance(status, int) or isinstance(status, bool):
        return False
    if not isinstance(body, str):
        return False
    if not isinstance(stored_at, (int, float)) or isinstance(stored_at, bool):
        return False
    return _is_representable(stored_at)


def _decode(raw: object) -> CachedResponse | None:
    """Build an entry from decoded JSON, rejecting anything malformed.

    Returns:
        The entry, or ``None`` if the payload is not a well-formed one.
    """
    if not isinstance(raw, dict):
        return None
    entry = cast("dict[str, object]", raw)
    status, body, stored_at = entry.get("status"), entry.get("body"), entry.get("at")
    headers = entry.get("headers")
    if not _is_entry_shape(status, body, stored_at) or not _is_string_map(headers):
        return None
    return CachedResponse(
        status=cast("int", status),
        body=cast("str", body),
        headers=cast("dict[str, str]", headers),
        stored_at=float(cast("float", stored_at)),
    )


def load(key: str) -> CachedResponse | None:
    """Read one entry, treating any unreadable entry as absent.

    A cache is disposable, so a truncated write, a partial disk, or a file
    from a future format must degrade to a miss. Raising here would make a
    corrupt byte on disk fatal to a command that could simply refetch.

    Args:
        key: The cache key.

    Returns:
        The stored entry, or ``None`` on a miss or a damaged entry.
    """
    if not settings().enabled:
        return None
    try:
        raw = cast("object", json.loads(_path_for(key).read_text(encoding="utf-8")))
    except _UNREADABLE:
        return None
    return _decode(raw)


def _kept_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name.lower(): value
        for name, value in headers.items()
        if name.lower() in _STORED_HEADERS
    }


def _atomic_write(directory: Path, key: str, payload: dict[str, object]) -> None:
    """Write one entry via a temporary file moved into place.

    A reader therefore sees either the previous entry or the complete new
    one, never a half-written file, however the process is interrupted.

    Raises:
        OSError: If the directory or the file cannot be written; the partial
            temporary file is removed first.
    """
    directory.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        _ = Path(temporary).replace(directory / f"{key}.json")
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise


def _expired(entry: Path, at: float) -> bool:
    """Whether one directory member is an entry of ours past :data:`MAX_AGE`.

    The name must be one :func:`key_for` could have produced, so nothing the
    user happens to keep in the same directory is ever a candidate.

    Returns:
        ``True`` only for a stale entry this cache wrote itself.
    """
    if not _KEY_PATTERN.match(entry.name):
        return False
    try:
        return at - entry.stat().st_mtime > MAX_AGE
    except OSError:
        return False


def _prune(directory: Path, at: float) -> None:
    """Delete this cache's entries older than :data:`MAX_AGE`, once per process.

    Judged by file modification time rather than the stored timestamp, so
    pruning costs one directory scan instead of reading and parsing every
    entry — which would make writes more expensive the more the cache holds,
    the opposite of what a cache is for.
    """
    if _PRUNED:
        return
    _PRUNED.append(True)
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        if _expired(entry, at):
            with suppress(OSError):
                entry.unlink(missing_ok=True)


def _write(key: str, payload: dict[str, object]) -> None:
    """Store one entry, unless the cache is off or cannot be written.

    The ``enabled`` check belongs here rather than only in :func:`load`: the
    setting says whether the cache is used *at all*, so honouring it on the
    read side alone would still leave files on disk for a caller that asked
    for none. This is the single funnel for both :func:`store` and
    :func:`touch`, so one guard covers every write.

    A read-only home directory, a full disk, or a missing permission is not a
    reason to fail a command that already has its answer; the next run simply
    fetches again.
    """
    if not settings().enabled:
        return
    directory = entries_directory()
    try:
        _atomic_write(directory, key, payload)
    except OSError:
        return
    _prune(directory, now())


def store(
    key: str, *, url: str, status: int, body: str, headers: dict[str, str]
) -> None:
    """Store one successful response.

    Args:
        key: The cache key.
        url: The request URL, stored with credentials redacted.
        status: The response status.
        body: The decoded response body.
        headers: Response headers; only an allowlist is kept.
    """
    _write(
        key,
        {
            "url": redacted(url),
            "status": status,
            "body": body,
            "headers": _kept_headers(headers),
            "at": now(),
        },
    )
