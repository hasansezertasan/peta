"""Unit tests for the shared outbound HTTP client."""

import atexit
import threading
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import http

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit

_URL = "https://example.invalid/thing"


def test_every_caller_gets_the_same_client() -> None:
    # Connection reuse is the whole point: a per-call client would pool nothing.
    assert http.client() is http.client()


def test_requests_carry_the_peta_user_agent() -> None:
    request = http.client().build_request("GET", _URL)
    assert request.headers["user-agent"] == http.USER_AGENT
    assert request.headers["user-agent"].startswith("peta/")


def test_requests_carry_the_default_timeout() -> None:
    request = http.client().build_request("GET", _URL)
    expected = dict.fromkeys(("connect", "read", "write", "pool"), http.DEFAULT_TIMEOUT)
    assert request.extensions["timeout"] == expected


def test_threads_racing_the_first_call_share_one_client() -> None:
    # `functools.cache` never holds a lock across the wrapped call, so
    # simultaneous misses each run it. Without the init lock this builds one
    # client per thread, each pinned for the process's life by its own atexit
    # registration, leaving the first requests on separate pools.
    http._build_client.cache_clear()
    barrier = threading.Barrier(8)
    seen: list[httpx.Client] = []

    def race() -> None:
        _ = barrier.wait()
        seen.append(http.client())

    threads = [threading.Thread(target=race) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len({id(instance) for instance in seen}) == 1


def test_the_client_is_closed_at_interpreter_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The cache holds the only reference for the life of the process, so
    # without this the pool's sockets are reclaimed by the garbage collector
    # at shutdown and raise a ResourceWarning that `filterwarnings = ["error"]`
    # turns into a failure.
    registered: list[Callable[[], object]] = []
    monkeypatch.setattr(atexit, "register", registered.append)
    http._build_client.cache_clear()

    instance = http.client()

    assert instance.close in registered
    http._build_client.cache_clear()


def test_get_goes_through_the_shared_client(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"ok": True})

    response = http.get(_URL)

    assert response.json() == {"ok": True}
    assert fake_http.request.method == "GET"
    assert str(fake_http.request.url) == _URL


def test_get_passes_query_parameters(fake_http: FakeTransport) -> None:
    fake_http.reply(json={})

    _ = http.get(_URL, params={"key": "value"})

    assert fake_http.request.url.params["key"] == "value"


def test_post_sends_a_json_body(fake_http: FakeTransport) -> None:
    fake_http.reply(json={"ok": True})

    _ = http.post(_URL, json={"name": "pkg"})

    assert fake_http.request.method == "POST"
    assert fake_http.request.headers["content-type"] == "application/json"


def test_transport_failures_reach_the_caller(fake_http: FakeTransport) -> None:
    # Each source maps a request error onto its own error type, so the
    # transport must not swallow or translate it.
    fake_http.fail(httpx.ConnectError("refused"))

    with pytest.raises(httpx.ConnectError):
        _ = http.get(_URL)


def test_an_unregistered_request_fails_the_test(fake_http: FakeTransport) -> None:
    # The guard is what makes "no network in tests" enforced rather than
    # hoped for: an unmocked request must fail loudly, not slip out.
    assert fake_http.requests == []
    with pytest.raises(AssertionError, match="no reply registered"):
        _ = http.get(_URL)
