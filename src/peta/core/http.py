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
import zlib
from dataclasses import dataclass
from functools import cache as _memoize
from typing import TYPE_CHECKING, cast

import httpx

from peta.__metadata__ import PROJECT_NAME
from peta._version import __version__
from peta.core import cache
from peta.core.cache import Provenance
from peta.core.concurrency import MAX_WORKERS
from peta.core.output import utc_from, utc_now

if TYPE_CHECKING:
    # zlib's decompressor type is only published under a private name. It is
    # imported for annotations alone and never touched at runtime.
    from zlib import _Decompress  # pyright: ignore[reportPrivateUsage]

    from peta.core.cache import CachedResponse


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_RESPONSE_BYTES",
    "USER_AGENT",
    "Fetched",
    "OfflineError",
    "ResponseTooLargeError",
    "TransportPolicyError",
    "UnsafeURLError",
    "UnsupportedEncodingError",
    "client",
    "get",
    "keep",
    "post",
]

_NOT_MODIFIED = 304
_OK = 200


DEFAULT_TIMEOUT = 10.0
"""Per-request timeout, in seconds, applied to every outbound request."""

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
"""Largest response accepted from an untrusted source, in bytes.

Sized against real PyPI data, not a round guess: ``grpcio``'s JSON document is
already 9 MiB and its Simple API page 6.7 MiB, and both grow with every
release. A 10 MiB cap was 87% used by one popular package. This one leaves
room for years of growth while still bounding what a hostile index can make
peta hold in memory.
"""

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

    Redirects are refused rather than followed. It is already httpx's default,
    and stated anyway because the HTTPS check runs against the URL peta chose:
    a followed redirect would move the request past it, to another scheme or
    origin, and could carry a credentialed header to wherever the response
    pointed.

    Returns:
        A new pooled :class:`httpx.Client`.
    """
    instance = httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        # gzip only, stated rather than left to httpx: it advertises brotli
        # and zstd as soon as their packages are importable, and _read_body
        # bounds decompression for gzip alone.
        headers={"user-agent": USER_AGENT, "accept-encoding": "gzip"},
        follow_redirects=False,
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


class TransportPolicyError(httpx.RequestError):
    """A request peta refused, or could not start, before any reply existed.

    Derived from :class:`httpx.RequestError` so that these checks join the
    contract every source already handles. Each one maps a failed request onto
    its own error type by catching ``httpx.RequestError``; an exception outside
    that hierarchy reaches the CLI unhandled, which prints a traceback and no
    message at all. A request peta declined to send has failed in exactly the
    sense those handlers already describe.
    """


class UnsafeURLError(TransportPolicyError):
    """Raised before a request to a non-HTTPS URL can be sent."""


class ResponseTooLargeError(TransportPolicyError):
    """Raised when an untrusted source exceeds the response-size limit."""


def _checked_url(url: str) -> str:
    """Accept only absolute HTTPS URLs before constructing a request.

    Redirects remain disabled on the shared client, so a response cannot move a
    request to another origin or carry any caller-supplied headers there.

    Returns:
        The normalized HTTPS URL.

    Raises:
        UnsafeURLError: If the URL is not absolute HTTPS.
    """
    parsed = httpx.URL(url)
    if parsed.scheme != "https" or not parsed.host:
        msg = f"Refusing unsafe URL {cache.redacted(url)!r}; HTTPS is required."
        raise UnsafeURLError(msg)
    return str(parsed)


_TOO_LARGE = f"Response exceeds the {MAX_RESPONSE_BYTES}-byte limit."

_TRANSFER_HEADERS = frozenset({
    "content-encoding",
    "content-length",
    "transfer-encoding",
})
"""Headers that describe the body *on the wire*, not the body peta ends up with.

:func:`_checked_response` hands httpx bytes it has already decoded, so leaving
``content-encoding`` in place would make httpx decompress a second time and
fail on every gzipped response — which is most of them. ``content-length`` and
``transfer-encoding`` describe the same encoded stream and are equally wrong
afterwards; httpx recomputes the length from the content it is given.
"""


_BODYLESS = frozenset({204, 304})
"""Statuses that never carry a body, whatever their headers say.

A ``304`` may keep ``Content-Encoding: gzip`` because the header describes the
cached representation it vouches for, not a body it sends. Decoding its empty
stream would fail the end-of-stream check and break every revalidation
against a server or CDN that does this.
"""


class UnsupportedEncodingError(TransportPolicyError):
    """Raised when a response uses a content encoding peta did not ask for."""


def _decompressor(response: httpx.Response) -> _Decompress | None:
    """Choose how to decode a body, refusing any encoding peta cannot bound.

    Returns:
        A gzip decompressor, or ``None`` for a body sent as-is.

    Raises:
        UnsupportedEncodingError: If the body uses any other encoding.
    """
    encoding = cast("str", response.headers.get("content-encoding", "")).strip().lower()
    if encoding in {"", "identity"} or response.status_code in _BODYLESS:
        return None
    if encoding == "gzip":
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    msg = f"Refusing unrequested content encoding {encoding!r}."
    raise UnsupportedEncodingError(msg)


def _refuse_declared_oversize(response: httpx.Response) -> None:
    """Refuse a body whose declared length is already over the limit.

    Raises:
        ResponseTooLargeError: If ``content-length`` exceeds the limit.
    """
    declared = cast("str | None", response.headers.get("content-length"))
    if (
        declared is not None
        and declared.isdigit()
        and int(declared) > MAX_RESPONSE_BYTES
    ):
        raise ResponseTooLargeError(_TOO_LARGE)


_INFLATE_STEP = 1024 * 1024
"""Most output one decompression call may produce, in bytes."""

_AFTER_END = "Unexpected data after the end of the gzip stream."
_CUT_SHORT = "The gzip stream ended before its end-of-stream marker."


def _inflate_into(content: bytearray, decompressor: _Decompress, chunk: bytes) -> None:
    """Decompress one wire chunk into ``content`` a bounded step at a time.

    Each call is capped with ``max_length`` at one step, and never at more than
    one byte past the remaining budget, so the call that would cross the limit
    is the one that detects it, having allocated at most a step. Capping only
    at the budget would let a single call return the whole budget as a fresh
    object before it is copied into ``content`` — twice the limit at peak.

    Input arriving after the end of the gzip stream is refused rather than
    ignored. zlib keeps it in ``unused_data``, re-copying the whole buffer on
    every call, so a tiny valid member followed by an endless trailer grew
    memory without bound while the decoded body stayed small — 300 MiB of
    trailer peaked at 600 MiB. Taking that leftover as the next input makes
    it reach the end-of-stream check, holding at most one chunk.

    Raises:
        ResponseTooLargeError: If the decoded body exceeds the limit.
        DecodingError: If any data follows the end of the gzip stream.
    """
    data = chunk
    while data:
        if decompressor.eof:
            raise httpx.DecodingError(_AFTER_END)
        budget = MAX_RESPONSE_BYTES - len(content) + 1
        content += decompressor.decompress(data, max_length=min(budget, _INFLATE_STEP))
        if len(content) > MAX_RESPONSE_BYTES:
            raise ResponseTooLargeError(_TOO_LARGE)
        data = decompressor.unconsumed_tail or decompressor.unused_data


def _append(content: bytearray, decompressor: _Decompress | None, chunk: bytes) -> None:
    """Add one chunk of body to ``content``, decoding it if it is compressed.

    Raises:
        ResponseTooLargeError: If the decoded body exceeds the limit.
    """
    if decompressor is not None:
        _inflate_into(content, decompressor, chunk)
        return
    content += chunk
    if len(content) > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError(_TOO_LARGE)


def _measured(body: bytes) -> bytes:
    """Return a body already in memory, if it is within the limit.

    Returns:
        The body unchanged.

    Raises:
        ResponseTooLargeError: If the body exceeds the limit.
    """
    if len(body) > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError(_TOO_LARGE)
    return body


def _finish(content: bytearray, decompressor: _Decompress | None) -> None:
    """Drain a gzip decoder once the body has ended, refusing a truncated one.

    All input has been consumed by now — every call ran until nothing was
    left — so what ``flush`` returns is small, but it is measured like any
    other output. A stream that never reached its end marker was cut off, and
    handing back the part that arrived would pass a truncated body on as
    whole.

    Raises:
        DecodingError: If the gzip stream never reached its end marker.
    """
    if decompressor is None:
        return
    _append(content, None, decompressor.flush())
    if not decompressor.eof:
        raise httpx.DecodingError(_CUT_SHORT)


def _read_body(response: httpx.Response) -> bytes:
    """Read and decode a streamed body without ever holding more than the limit.

    Decoding is done here rather than by httpx, whose streaming decoder
    inflates each wire chunk in one call: a 64 KiB gzip chunk can expand to
    64 MiB before any length check sees it. :func:`_inflate_into` caps the
    output instead.

    Returns:
        The decoded body.
    """
    _refuse_declared_oversize(response)
    if response.is_stream_consumed:
        # A response built in memory arrives already read — and already
        # decoded — by httpx. That never happens to a network stream, which is
        # what ``send(stream=True)`` yields, so there is no compressed input
        # left to bound; the body is measured as it stands.
        return _measured(response.content)
    decompressor = _decompressor(response)
    content = bytearray()
    for chunk in response.iter_raw():
        _append(content, decompressor, chunk)
    _finish(content, decompressor)
    return bytes(content)


def _within_limit(response: httpx.Response) -> bytes:
    """Read a streamed body, stopping as soon as it grows past the limit.

    Returns:
        The decoded body.

    Raises:
        DecodingError: If a compressed body is corrupt, keeping the error
            inside the ``httpx.RequestError`` contract sources handle.
    """
    # Everything sits inside the ``try``: a streamed response holds a
    # connection checked out of the shared pool until it is closed, so raising
    # before ``close`` would leak one per refused reply, and a fan-out across
    # many packages could drain the pool.
    try:
        return _read_body(response)
    except zlib.error as exc:
        msg = f"Could not decode the response body: {exc}"
        raise httpx.DecodingError(msg) from exc
    finally:
        response.close()


def _checked_response(response: httpx.Response) -> httpx.Response:
    """Reject a response whose declared or received body exceeds the limit.

    Returns:
        The accepted response, carrying the already-decoded body.
    """
    content = _within_limit(response)
    headers = [
        (name, value)
        for name, value in response.headers.multi_items()
        if name.lower() not in _TRANSFER_HEADERS
    ]
    return httpx.Response(
        response.status_code, content=content, headers=headers, request=response.request
    )


def _send(request: httpx.Request) -> httpx.Response:
    """Send and consume a response without allowing an unbounded body in memory.

    Returns:
        The bounded, fully consumed response.
    """
    return _checked_response(client().send(request, stream=True))


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


def _revalidate(
    url: str,
    key: str,
    entry: CachedResponse | None,
    headers: dict[str, str] | None = None,
) -> Fetched:
    """Ask the source, offering any stored validator to save it resending.

    Returns:
        The live response, or the stored one if the source confirmed it.
    """
    _refuse_offline(url)
    request = client().build_request("GET", url)
    if headers:
        request.headers.update(headers)
    if entry is not None:
        request.headers.update(entry.validators)
    response = _send(request)
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


def _replayable(entry: CachedResponse | None) -> CachedResponse | None:
    """Drop a stored entry whose body is over the response-size limit.

    A replayed body never passes through the transport, so the limit has to
    be applied here too, or an entry written before the limit existed — or
    edited on disk — would be served at whatever size it is. Checked where
    entries are loaded, so a fresh hit, a stale offline answer, and a ``304``
    revalidation are all covered. Measured in UTF-8 bytes like a live body,
    and only encoded when the cheap character count cannot already decide.

    Returns:
        The entry, or ``None`` when its body is over the limit.
    """
    if entry is None:
        return None
    body = entry.body
    too_big = len(body) > MAX_RESPONSE_BYTES or (
        not body.isascii() and len(body.encode("utf-8")) > MAX_RESPONSE_BYTES
    )
    return None if too_big else entry


def _cached_get(
    url: str, ttl: int, scope: str, headers: dict[str, str] | None = None
) -> Fetched:
    """Serve a GET from the cache when possible, otherwise from the source.

    Returns:
        The response and where it came from.
    """
    key = cache.key_for("GET", url, scope)
    entry = None if cache.settings().refresh else _replayable(cache.load(key))
    if entry is not None and entry.is_fresh(ttl, cache.now()):
        return _served(entry, url)
    if cache.settings().offline:
        return _serve_offline(url, entry)
    return _revalidate(url, key, entry, headers=headers)


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
    headers: dict[str, str] | None = None,
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
        headers: Extra request headers merged onto the shared client's
            defaults, for content negotiation or similar per-source needs.
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
    built_url = httpx.URL(url) if params is None else httpx.URL(url, params=params)
    full = _checked_url(str(built_url))
    if ttl is None:
        _refuse_offline(full)
        request = client().build_request("GET", full)
        if headers:
            request.headers.update(headers)
        return Fetched(_send(request), Provenance("live", utc_now()))
    return _cached_get(full, ttl, scope, headers=headers)


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
    full = _checked_url(url)
    _refuse_offline(full)
    request = client().build_request("POST", full, json=json)
    return Fetched(_send(request), Provenance("live", utc_now()))
