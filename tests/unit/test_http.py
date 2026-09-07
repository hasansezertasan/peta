"""Unit tests for the shared outbound HTTP client."""

import atexit
import threading
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import cache, http

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

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

    fetched = http.get(_URL)

    assert fetched.response.json() == {"ok": True}
    assert fetched.freshness == "live"
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


class TestCaching:
    """The cache as the sources see it, through :func:`peta.core.http.get`."""

    def test_a_fresh_entry_is_served_without_asking_the_source(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})

        _ = http.get(_URL, ttl=60)
        second = http.get(_URL, ttl=60)

        assert second.freshness == "cached"
        assert second.response.json() == {"v": 1}
        assert len(fake_http.requests) == 1

    def test_an_expired_entry_is_fetched_again(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(json={"v": 1})

        _ = http.get(_URL, ttl=60)
        frozen_clock[0] += 61
        second = http.get(_URL, ttl=60)

        assert second.freshness == "live"
        assert len(fake_http.requests) == 2

    def test_no_ttl_bypasses_the_cache_entirely(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})

        first = http.get(_URL)
        second = http.get(_URL)

        assert (first.freshness, second.freshness) == ("live", "live")
        assert len(fake_http.requests) == 2
        assert list(cache_dir.glob("*.json")) == []

    def test_an_error_response_is_not_cached(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # An error describes this moment, not the package. Storing one would
        # turn a transient outage into a persistent wrong answer.
        assert cache.settings().directory == cache_dir
        fake_http.reply(status=500)

        _ = http.get(_URL, ttl=60)

        assert list(cache_dir.glob("*.json")) == []

    def test_refresh_ignores_a_fresh_entry(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        fake_http.reply(json={"v": 1})
        _ = http.get(_URL, ttl=60)
        cache.configure(directory=cache_dir, refresh=True)

        second = http.get(_URL, ttl=60)

        assert second.freshness == "live"
        assert len(fake_http.requests) == 2


class TestConditionalRequests:
    def test_a_stale_entry_offers_its_validator(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(json={"v": 1}, headers={"etag": 'W/"v1"'})
        _ = http.get(_URL, ttl=60)
        frozen_clock[0] += 61

        _ = http.get(_URL, ttl=60)

        assert fake_http.requests[1].headers["if-none-match"] == 'W/"v1"'

    def test_a_304_serves_the_stored_body(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(url="?first", json={"v": 1}, headers={"etag": 'W/"v1"'})
        first = http.get(_URL + "?first", ttl=60)
        assert first.freshness == "live"
        frozen_clock[0] += 61
        # The source now answers "unchanged" with no body at all.
        fake_http.reply(url="?first", status=304)

        second = http.get(_URL + "?first", ttl=60)

        assert second.freshness == "revalidated"
        assert second.response.json() == {"v": 1}

    def test_a_304_restamps_the_entry_so_the_next_read_is_a_hit(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(url="?r", json={"v": 1}, headers={"etag": "e"})
        _ = http.get(_URL + "?r", ttl=60)
        frozen_clock[0] += 61
        fake_http.reply(url="?r", status=304)
        _ = http.get(_URL + "?r", ttl=60)

        third = http.get(_URL + "?r", ttl=60)

        assert third.freshness == "cached"
        # Two requests total: the original and the one revalidation.
        assert len(fake_http.requests) == 2


class TestOffline:
    def test_a_cache_miss_names_the_url_it_could_not_answer(
        self, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError, match=_URL):
            _ = http.get(_URL, ttl=60)

    def test_no_request_is_attempted(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError):
            _ = http.get(_URL, ttl=60)

        assert fake_http.requests == []

    def test_a_stale_entry_is_still_served(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        # Past its TTL is not the same as wrong, and someone who asked for
        # offline has already said they prefer an old answer to none.
        fake_http.reply(json={"v": 1})
        _ = http.get(_URL, ttl=60)
        frozen_clock[0] += 10_000
        cache.configure(directory=cache_dir, offline=True)

        served = http.get(_URL, ttl=60)

        assert served.freshness == "cached"
        assert served.response.json() == {"v": 1}
        assert len(fake_http.requests) == 1

    def test_an_uncacheable_request_is_refused_rather_than_sent(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError):
            _ = http.get(_URL)

        assert fake_http.requests == []

    def test_a_post_is_refused(self, fake_http: FakeTransport, cache_dir: Path) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError):
            _ = http.post(_URL, json={"q": 1})

        assert fake_http.requests == []


class TestPost:
    def test_a_post_is_never_cached(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"vulns": []})

        first = http.post(_URL, json={"q": 1})
        second = http.post(_URL, json={"q": 1})

        assert (first.freshness, second.freshness) == ("live", "live")
        assert len(fake_http.requests) == 2
        assert list(cache_dir.glob("*.json")) == []
