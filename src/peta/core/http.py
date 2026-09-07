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

if TYPE_CHECKING:
    from peta.core.cache import CachedResponse, Freshness

__all__ = [
    "DEFAULT_TIMEOUT",
    "USER_AGENT",
    "Fetched",
    "OfflineError",
    "client",
    "get",
    "post",
]

_NOT_MODIFIED = 304
_OK = 200


DEFAULT_TIMEOUT = 10.0
"""Per-request timeout, in seconds, applied to every outbound request."""

USER_AGENT = f"{PROJECT_NAME}/{__version__}"
"""Identifies peta to the APIs it queries, as their usage guidelines ask."""

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
    instance = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"user-agent": USER_AGENT})
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
    """A response, and where it came from."""

    response: httpx.Response
    freshness: Freshness


class OfflineError(Exception):
    """Raised when offline mode is on and the cache cannot answer.

    Distinct from :class:`~peta.core.remote.NetworkError`: nothing went
    wrong, peta was told not to use the network and does not hold the answer.
    Conflating the two would tell a user to check their connection when the
    fix is to drop ``--offline`` or warm the cache.
    """

    def __init__(self, url: str) -> None:
        """Name the request that could not be served offline."""
        self.url: str = url
        super().__init__(f"offline and no cached response for {url}")


def _replay(entry: CachedResponse, request: httpx.Request) -> httpx.Response:
    """Rebuild a real response from a stored entry.

    Returned as an ``httpx.Response`` bound to ``request`` so a cached answer
    supports everything a live one does, ``raise_for_status`` included, and no
    source needs to know whether it was served from disk.

    Returns:
        The reconstructed response.
    """
    return httpx.Response(
        entry.status, text=entry.body, headers=entry.headers, request=request
    )


def _send(request: httpx.Request) -> httpx.Response:
    """Send a request, refusing outright when offline.

    Returns:
        The live response.

    Raises:
        OfflineError: If offline mode is on.
    """
    if cache.settings().offline:
        raise OfflineError(str(request.url))
    return client().send(request)


def _serve_offline(request: httpx.Request, entry: CachedResponse | None) -> Fetched:
    """Answer from the cache while offline, even if the entry is stale.

    Past its TTL is not the same as wrong, and a user who asked for offline
    has already said they prefer an old answer to no answer. The staleness is
    not hidden: the reported freshness is ``cached``, so output says where the
    data came from.

    Returns:
        The stored response.

    Raises:
        OfflineError: If nothing is stored for this request.
    """
    if entry is None:
        raise OfflineError(str(request.url))
    return Fetched(_replay(entry, request), "cached")


def _revalidate(
    request: httpx.Request, key: str, entry: CachedResponse | None
) -> Fetched:
    """Ask the source, offering any stored validator to save it resending.

    Returns:
        The live response, or the stored one if the source confirmed it.
    """
    if entry is not None:
        request.headers.update(entry.validators)
    response = _send(request)
    url = str(request.url)
    if response.status_code == _NOT_MODIFIED and entry is not None:
        cache.touch(key, entry, url=url)
        return Fetched(_replay(entry, request), "revalidated")
    if response.status_code == _OK:
        cache.store(
            key,
            url=url,
            status=response.status_code,
            body=response.text,
            headers=dict(response.headers),
        )
    return Fetched(response, "live")


def _cached_get(request: httpx.Request, ttl: int) -> Fetched:
    """Serve a GET from the cache when possible, otherwise from the source.

    Returns:
        The response and where it came from.
    """
    key = cache.key_for("GET", str(request.url))
    entry = None if cache.settings().refresh else cache.load(key)
    if entry is not None and entry.is_fresh(ttl, cache.now()):
        return Fetched(_replay(entry, request), "cached")
    if cache.settings().offline:
        return _serve_offline(request, entry)
    return _revalidate(request, key, entry)


def get(
    url: str, *, params: dict[str, str] | None = None, ttl: int | None = None
) -> Fetched:
    """Send a GET request, using the cache when the caller allows it.

    A transport-level ``httpx.RequestError`` propagates untouched: each
    source maps it onto its own error type.

    Args:
        url: The absolute URL to request.
        params: Optional query-string parameters.
        ttl: How long a stored response stays usable, in seconds. ``None``
            bypasses the cache entirely, for a URL whose answer should never
            be reused.

    An :class:`OfflineError` propagates from the send path when offline mode
    is on and the cache cannot answer.

    Returns:
        The response and where it came from.
    """
    request = client().build_request("GET", url, params=params)
    if ttl is None:
        return Fetched(_send(request), "live")
    return _cached_get(request, ttl)


def post(url: str, *, json: dict[str, object]) -> Fetched:
    """Send a JSON POST request over the shared client.

    Never cached: a POST body carries the question, and peta's only POST
    source is an advisory query whose request shape is about to change with
    batching. Offline mode still refuses it rather than pretending.

    A transport-level ``httpx.RequestError`` propagates untouched: each
    source maps it onto its own error type.

    Args:
        url: The absolute URL to request.
        json: The request body, serialized as JSON.

    An :class:`OfflineError` propagates from the send path when offline mode
    is on.

    Returns:
        The response and where it came from, always ``live``.
    """
    request = client().build_request("POST", url, json=json)
    return Fetched(_send(request), "live")
