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
"""

from __future__ import annotations

import atexit
import threading
from functools import cache

import httpx

from peta.__metadata__ import PROJECT_NAME
from peta._version import __version__

__all__ = ["DEFAULT_TIMEOUT", "USER_AGENT", "client", "get", "post"]


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


@cache
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


def get(url: str, *, params: dict[str, str] | None = None) -> httpx.Response:
    """Send a GET request over the shared client.

    A transport-level ``httpx.RequestError`` propagates untouched: each
    source maps it onto its own error type.

    Args:
        url: The absolute URL to request.
        params: Optional query-string parameters.

    Returns:
        The response, whatever its status; callers decide what a status means.
    """
    return client().get(url, params=params)


def post(url: str, *, json: dict[str, object]) -> httpx.Response:
    """Send a JSON POST request over the shared client.

    A transport-level ``httpx.RequestError`` propagates untouched: each
    source maps it onto its own error type.

    Args:
        url: The absolute URL to request.
        json: The request body, serialized as JSON.

    Returns:
        The response, whatever its status; callers decide what a status means.
    """
    return client().post(url, json=json)
