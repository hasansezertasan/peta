"""The one outbound HTTP client every peta source shares.

Each source used to call the top-level ``httpx.get``/``httpx.post`` helpers,
which build a throwaway client per call. A dependency tree or a comparison
therefore paid for a fresh connection and TLS handshake on every request to the
same host. Routing every request through a single pooled client lets them reuse
connections, and leaves one place for the caching and concurrency layers to wrap
instead of four call sites in three modules.

Only transport lives here. Status handling, decoding, and validation stay with
each source, because they map failures onto different error types: a PyPI
lookup is fatal (:class:`~peta.core.remote.NetworkError`) while an enrichment
lookup is not (:class:`~peta.core.validation.EnrichmentError`).

Caching also lives here rather than in each source, so one implementation of
"is the stored copy still good, and if not can the source just confirm it"
serves every URL peta fetches. Whether a given URL is cacheable at all, and
for how long, stays with the caller: see :mod:`peta.core.cache`.
"""

from __future__ import annotations

import atexit
import threading
from dataclasses import dataclass
from functools import cache as _memoize
from typing import TYPE_CHECKING

import httpx

from peta.__metadata__ import PROJECT_NAME
from peta._version import __version__
from peta.core import cache
from peta.core.cache import Provenance
from peta.core.concurrency import MAX_WORKERS
from peta.core.output import utc_from, utc_now

if TYPE_CHECKING:
    from peta.core.cache import CachedResponse

__all__ = [
    "DEFAULT_TIMEOUT",
    "USER_AGENT",
    "Fetched",
    "OfflineError",
    "client",
    "get",
    "keep",
    "post",
]

_NOT_MODIFIED = 304
_OK = 200


DEFAULT_TIMEOUT = 10.0
"""Per-request timeout, in seconds, applied to every outbound request."""

USER_AGENT = f"{PROJECT_NAME}/{__version__}"
"""Identifies peta to the APIs it queries, as their usage guidelines ask."""

MAX_CONNECTIONS = MAX_WORKERS
"""The real bound on concurrent requests, whatever the thread count.

Sockets are the scarce resource, not threads, and this limit applies to the
one shared client — so it holds across every concurrent fan-out at once,
which a per-call worker count cannot promise. Matched to
:data:`peta.core.concurrency.MAX_WORKERS` so a fan-out is never throttled by
a bound narrower than the work it was allowed to start.
"""

_INIT_LOCK = threading.Lock()
"""Serializes first use, since ``functools.cache`` does not.

``cache`` never holds a lock across the wrapped call, so simultaneous misses
each run it: N threads racing the first request would build N clients, and
each would be pinned for the process's life by its own ``atexit``
registration. That would leave the first requests on separate pools and an
extra pool alive until shutdown — precisely what this module exists to
prevent. Nothing in peta is threaded today, but bounded concurrency is the
next piece of transport work, so the guard goes in with the client rather
than after something has already raced it.
"""


@_memoize
def _build_client() -> httpx.Client:
    """Construct the pooled client and arrange for it to be closed.

    Closing is registered with :mod:`atexit` because the cache holds the only
    reference for the life of the process: without it the pool's sockets are
    reclaimed by the garbage collector at shutdown, which raises a
    ``ResourceWarning`` that this project's ``filterwarnings = ["error"]``
    turns into a test failure.

    Returns:
        A new pooled :class:`httpx.Client`.
    """
    instance = httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        headers={"user-agent": USER_AGENT},
        limits=httpx.Limits(
            max_connections=MAX_CONNECTIONS, max_keepalive_connections=MAX_CONNECTIONS
        ),
    )
    _ = atexit.register(instance.close)
    return instance


def client() -> httpx.Client:
    """Return the process-wide pooled client, building it on first use.

    Built on demand rather than at import time because constructing a client
    loads the system CA bundle, which costs tens of milliseconds — a price
    ``peta files`` and ``peta info --local`` should not pay to import a module
    they never send a request through.

    Returns:
        The shared :class:`httpx.Client`.
    """
    with _INIT_LOCK:
        return _build_client()


@dataclass(frozen=True)
class Fetched:
    """A response, where it came from, and whether it may still be cached."""

    response: httpx.Response
    provenance: Provenance
    cache_key: str | None = None
    """Set only for a live response the caller may still choose to keep.

    ``None`` for anything already stored, or for a response that must never
    be stored, so :func:`keep` is safe to call unconditionally.
    """


class OfflineError(Exception):
    """Raised when offline mode is on and the cache cannot answer.

    Distinct from :class:`~peta.core.remote.NetworkError`: nothing went
    wrong, peta was told not to use the network and does not hold the answer.
    Conflating the two would tell a user to check their connection when the
    fix is to drop ``--offline`` or warm the cache.
    """

    def __init__(self, url: str) -> None:
        """Name the request that could not be served offline.

        The URL is redacted here rather than at each raise site, so no future
        caller can leak a credential by forgetting to. Libraries.io takes its
        API key in the query string, and this message is surfaced to users:
        for a fatal lookup it becomes the ``offline_unavailable`` error in the
        envelope, and for an optional one it survives as the ``__cause__`` of
        the source failure, where any traceback would print it.
        """
        self.url: str = cache.redacted(url)
        super().__init__(f"offline and no cached response for {self.url}")


def _bind(url: str) -> httpx.Request:
    """Make a request object to bind a replayed response to.

    Deliberately not built through the client: a cache hit must not pay for
    constructing one, which loads the system CA bundle, and an offline
    lookup must not fail because TLS configuration is broken in an
    environment that never intends to make a request.

    Returns:
        A bare request carrying only the method and URL.
    """
    return httpx.Request("GET", url)


def _replay(entry: CachedResponse, url: str) -> httpx.Response:
    """Rebuild a real response from a stored entry.

    Returned as an ``httpx.Response`` so a cached answer supports everything
    a live one does, ``raise_for_status`` included, and no source needs to
    know whether it was served from disk.

    Returns:
        The reconstructed response.
    """
    return httpx.Response(
        entry.status, text=entry.body, headers=entry.headers, request=_bind(url)
    )


def _served(entry: CachedResponse, url: str) -> Fetched:
    """Present a stored entry as a fetch result, dated when it was stored.

    Returns:
        The replayed response, reporting the source's own retrieval time.
    """
    return Fetched(_replay(entry, url), Provenance("cached", utc_from(entry.stored_at)))


def _refuse_offline(url: str) -> None:
    """Stop before anything is built when offline mode is on.

    Called ahead of every ``client()`` construction rather than at the point
    of sending: building a client loads the system CA bundle and can fail
    outright where TLS is misconfigured, which must not turn a defined
    offline outcome into a generic transport exception.

    Raises:
        OfflineError: If offline mode is on.
    """
    if cache.settings().offline:
        raise OfflineError(url)


def _serve_offline(url: str, entry: CachedResponse | None) -> Fetched:
    """Answer from the cache while offline, even if the entry is stale.

    Past its TTL is not the same as wrong, and a user who asked for offline
    has already said they prefer an old answer to no answer. The staleness is
    not hidden: the result is reported as ``cached`` and dated when it was
    stored, so output says both where the data came from and how old it is.

    Returns:
        The stored response.

    Raises:
        OfflineError: If nothing is stored for this request.
    """
    if entry is None:
        raise OfflineError(url)
    return _served(entry, url)


def _revalidate(url: str, key: str, entry: CachedResponse | None) -> Fetched:
    """Ask the source, offering any stored validator to save it resending.

    Returns:
        The live response, or the stored one if the source confirmed it.
    """
    _refuse_offline(url)
    request = client().build_request("GET", url)
    if entry is not None:
        request.headers.update(entry.validators)
    response = client().send(request)
    if response.status_code == _NOT_MODIFIED and entry is not None:
        # Restamped by ``keep``, not here: the stored body still has to
        # satisfy the caller's decoder, which a stricter parser or a
        # body-level corruption could now reject. Blessing it before that
        # check would keep an unusable entry fresh for another full TTL.
        # The source confirmed the body just now, so this counts as a
        # current retrieval of it rather than a replay of an old one.
        return Fetched(
            _replay(entry, url), Provenance("revalidated", utc_now()), cache_key=key
        )
    return Fetched(response, Provenance("live", utc_now()), cache_key=key)


def _cached_get(url: str, ttl: int, scope: str) -> Fetched:
    """Serve a GET from the cache when possible, otherwise from the source.

    Returns:
        The response and where it came from.
    """
    key = cache.key_for("GET", url, scope)
    entry = None if cache.settings().refresh else cache.load(key)
    if entry is not None and entry.is_fresh(ttl, cache.now()):
        return _served(entry, url)
    if cache.settings().offline:
        return _serve_offline(url, entry)
    return _revalidate(url, key, entry)


def keep(fetched: Fetched) -> None:
    """Store a live response the caller has confirmed it could actually use.

    Storing on arrival would cache a body the source-specific decoder then
    rejects — a ``200`` carrying an error page, or truncated JSON — and every
    later request would replay that same unusable response until the TTL
    expired, up to a month for pinned metadata. A transient upstream fault
    would become a persistent one.

    So nothing is written until the caller has decoded and validated the
    body and says so by calling this. Failing to call it means the response
    is simply not cached, which costs a refetch; the opposite default would
    poison the cache.

    Args:
        fetched: The result to store. Ignored unless it is a live ``200``
            still carrying a cache key, so callers need not check.
    """
    if fetched.cache_key is None or fetched.response.status_code != _OK:
        return
    cache.store(
        fetched.cache_key,
        url=str(fetched.response.request.url),
        status=fetched.response.status_code,
        body=fetched.response.text,
        headers=dict(fetched.response.headers),
    )


def get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    ttl: int | None = None,
    scope: str = "",
) -> Fetched:
    """Send a GET request, using the cache when the caller allows it.

    A transport-level ``httpx.RequestError`` propagates untouched, and an
    :class:`OfflineError` propagates when offline mode is on and the cache
    cannot answer; each source maps them onto its own error type.

    A live result is not cached until the caller confirms the body was usable
    by passing it to :func:`keep`.

    Args:
        url: The absolute URL to request.
        params: Optional query-string parameters.
        ttl: How long a stored response stays usable, in seconds. ``None``
            bypasses the cache entirely, for a URL whose answer should never
            be reused.
        scope: Distinguishes consumers that fetch the same URL but validate
            different parts of it, so neither replays a body the other
            accepted. See :func:`peta.core.cache.key_for`.

    Returns:
        The response and where it came from.
    """
    # Merged here rather than by the client, so a cache hit never constructs
    # one; the result is byte-identical to what ``build_request`` produces.
    # ``params=None`` is not passed through: httpx reads that as "replace the
    # query with nothing" and silently drops any query already in the URL,
    # where ``build_request`` leaves it alone.
    full = str(httpx.URL(url) if params is None else httpx.URL(url, params=params))
    if ttl is None:
        _refuse_offline(full)
        return Fetched(
            client().send(client().build_request("GET", full)),
            Provenance("live", utc_now()),
        )
    return _cached_get(full, ttl, scope)


def post(url: str, *, json: dict[str, object]) -> Fetched:
    """Send a JSON POST request over the shared client.

    Never cached: a POST body carries the question, and peta's only POST
    source is an advisory query whose request shape is about to change with
    batching. Offline mode still refuses it rather than pretending.

    A transport-level ``httpx.RequestError`` propagates untouched, and an
    :class:`OfflineError` propagates when offline mode is on.

    Args:
        url: The absolute URL to request.
        json: The request body, serialized as JSON.

    Returns:
        The response and where it came from, always ``live``.
    """
    _refuse_offline(url)
    request = client().build_request("POST", url, json=json)
    return Fetched(client().send(request), Provenance("live", utc_now()))
