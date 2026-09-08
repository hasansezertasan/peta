"""Unit tests for the shared outbound HTTP client."""

import atexit
import threading
from typing import TYPE_CHECKING

import httpx
import pytest

from peta.core import cache, http, stats
from peta.core.output import utc_from
from peta.core.validation import EnrichmentError

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
    assert fetched.provenance.freshness == "live"
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

        http.keep(http.get(_URL, ttl=60))
        second = http.get(_URL, ttl=60)

        assert second.provenance.freshness == "cached"
        assert second.response.json() == {"v": 1}
        assert len(fake_http.requests) == 1

    def test_an_expired_entry_is_fetched_again(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(json={"v": 1})

        http.keep(http.get(_URL, ttl=60))
        frozen_clock[0] += 61
        second = http.get(_URL, ttl=60)

        assert second.provenance.freshness == "live"
        assert len(fake_http.requests) == 2

    def test_no_ttl_bypasses_the_cache_entirely(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})

        first = http.get(_URL)
        http.keep(first)
        second = http.get(_URL)

        assert (first.provenance.freshness, second.provenance.freshness) == (
            "live",
            "live",
        )
        assert len(fake_http.requests) == 2
        assert list(cache_dir.glob("*.json")) == []

    def test_an_error_response_is_not_cached(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # An error describes this moment, not the package. Storing one would
        # turn a transient outage into a persistent wrong answer.
        assert cache.settings().directory == cache_dir
        fake_http.reply(status=500)

        http.keep(http.get(_URL, ttl=60))

        assert list(cache_dir.glob("*.json")) == []

    def test_refresh_ignores_a_fresh_entry(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))
        cache.configure(directory=cache_dir, refresh=True)

        second = http.get(_URL, ttl=60)

        assert second.provenance.freshness == "live"
        assert len(fake_http.requests) == 2


class TestConditionalRequests:
    def test_a_stale_entry_offers_its_validator(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(json={"v": 1}, headers={"etag": 'W/"v1"'})
        http.keep(http.get(_URL, ttl=60))
        frozen_clock[0] += 61

        http.keep(http.get(_URL, ttl=60))

        assert fake_http.requests[1].headers["if-none-match"] == 'W/"v1"'

    def test_a_304_serves_the_stored_body(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(url="?first", json={"v": 1}, headers={"etag": 'W/"v1"'})
        first = http.get(_URL + "?first", ttl=60)
        http.keep(first)
        assert first.provenance.freshness == "live"
        frozen_clock[0] += 61
        # The source now answers "unchanged" with no body at all.
        fake_http.reply(url="?first", status=304)

        second = http.get(_URL + "?first", ttl=60)

        assert second.provenance.freshness == "revalidated"
        assert second.response.json() == {"v": 1}

    def test_a_304_restamps_the_entry_so_the_next_read_is_a_hit(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache_dir.parent.exists()
        fake_http.reply(url="?r", json={"v": 1}, headers={"etag": "e"})
        http.keep(http.get(_URL + "?r", ttl=60))
        frozen_clock[0] += 61
        fake_http.reply(url="?r", status=304)
        http.keep(http.get(_URL + "?r", ttl=60))

        third = http.get(_URL + "?r", ttl=60)

        assert third.provenance.freshness == "cached"
        # Two requests total: the original and the one revalidation.
        assert len(fake_http.requests) == 2


class TestOffline:
    def test_a_cache_miss_names_the_url_it_could_not_answer(
        self, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError, match=_URL):
            http.keep(http.get(_URL, ttl=60))

    def test_no_request_is_attempted(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(http.OfflineError):
            http.keep(http.get(_URL, ttl=60))

        assert fake_http.requests == []

    def test_a_stale_entry_is_still_served(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        # Past its TTL is not the same as wrong, and someone who asked for
        # offline has already said they prefer an old answer to none.
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))
        frozen_clock[0] += 10_000
        cache.configure(directory=cache_dir, offline=True)

        served = http.get(_URL, ttl=60)

        assert served.provenance.freshness == "cached"
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
        http.keep(first)
        second = http.post(_URL, json={"q": 1})

        assert (first.provenance.freshness, second.provenance.freshness) == (
            "live",
            "live",
        )
        assert len(fake_http.requests) == 2
        assert list(cache_dir.glob("*.json")) == []


class TestUrlBuilding:
    def test_a_query_already_in_the_url_survives(
        self, fake_http: FakeTransport
    ) -> None:
        # httpx.URL(url, params=None) reads None as "replace the query with
        # nothing" and drops it, unlike Client.build_request.
        fake_http.reply(json={})

        _ = http.get("https://example.invalid/thing?page=2")

        assert fake_http.request.url.params["page"] == "2"

    def test_explicit_params_are_merged(self, fake_http: FakeTransport) -> None:
        fake_http.reply(json={})

        _ = http.get(_URL, params={"period": "day"}, ttl=60)

        assert fake_http.request.url.params["period"] == "day"

    def test_the_cache_key_covers_the_merged_url(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # Two lookups differing only in a query parameter are different
        # questions and must not share one entry.
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={})
        http.keep(http.get(_URL, params={"period": "day"}, ttl=60))

        second = http.get(_URL, params={"period": "month"}, ttl=60)

        assert second.provenance.freshness == "live"


class TestKeep:
    def test_a_response_is_not_stored_until_the_caller_keeps_it(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # The P1 this guards: storing on arrival would cache a 200 whose body
        # the source then rejects, and replay it until the TTL expired.
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})

        fetched = http.get(_URL, ttl=60)

        assert list(cache_dir.glob("*.json")) == []
        http.keep(fetched)
        assert len(list(cache_dir.glob("*.json"))) == 1

    def test_an_unusable_body_is_never_replayed(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # A 200 carrying an error page: the caller does not keep it, so the
        # next request reaches the recovered source instead of the bad body.
        assert cache.settings().directory == cache_dir
        fake_http.reply(text="<html>502 Bad Gateway</html>")
        first = http.get(_URL, ttl=60)
        assert first.provenance.freshness == "live"
        # Caller decodes, fails, and does not keep.

        fake_http.reply(json={"v": 1})
        second = http.get(_URL, ttl=60)

        assert second.provenance.freshness == "live"
        assert second.response.json() == {"v": 1}
        assert len(fake_http.requests) == 2

    def test_keeping_a_non_success_is_ignored(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(status=500)

        http.keep(http.get(_URL, ttl=60))

        assert list(cache_dir.glob("*.json")) == []

    def test_keeping_a_cached_result_is_a_no_op(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        # Safe to call unconditionally: a replayed entry carries no key.
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))

        served = http.get(_URL, ttl=60)
        http.keep(served)

        assert served.cache_key is None
        assert len(list(cache_dir.glob("*.json"))) == 1


class TestRetrievalTime:
    def test_a_cached_response_reports_when_it_was_stored(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        # A response stored days ago must not claim it was retrieved now, or
        # provenance is worse than absent.
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=86_400))
        stored_at = frozen_clock[0]
        frozen_clock[0] += 3 * 3600

        served = http.get(_URL, ttl=86_400)

        assert served.provenance.freshness == "cached"
        assert served.provenance.retrieved_at == utc_from(stored_at)

    def test_a_revalidated_response_is_dated_now(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        # The source confirmed the body just now, so this is a current
        # retrieval of it rather than a replay of an old one.
        assert cache.settings().directory == cache_dir
        fake_http.reply(url="?v", json={"v": 1}, headers={"etag": "e"})
        http.keep(http.get(_URL + "?v", ttl=60))
        frozen_clock[0] += 61
        fake_http.reply(url="?v", status=304)

        again = http.get(_URL + "?v", ttl=60)

        assert again.provenance.freshness == "revalidated"
        assert again.provenance.retrieved_at != utc_from(frozen_clock[0] - 61)


class TestNoClientForCacheHits:
    def test_a_cache_hit_never_builds_the_pooled_client(
        self, fake_http: FakeTransport, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Constructing a client loads the system CA bundle, tens of
        # milliseconds, which a cache hit exists to avoid paying. It also
        # fails outright where TLS config is broken, which must not stop
        # --offline reading otherwise valid data.
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))

        def explode() -> httpx.Client:
            msg = "no TLS available here"
            raise RuntimeError(msg)

        monkeypatch.setattr(http, "client", explode)

        served = http.get(_URL, ttl=60)

        assert served.provenance.freshness == "cached"
        assert served.response.json() == {"v": 1}

    def test_offline_reads_the_cache_without_a_client(
        self, fake_http: FakeTransport, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))
        cache.configure(directory=cache_dir, offline=True)

        def explode() -> httpx.Client:
            msg = "no TLS available here"
            raise RuntimeError(msg)

        monkeypatch.setattr(http, "client", explode)

        assert http.get(_URL, ttl=60).provenance.freshness == "cached"

    def test_an_offline_miss_still_raises_without_a_client(
        self, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)

        def explode() -> httpx.Client:
            msg = "no TLS available here"
            raise RuntimeError(msg)

        monkeypatch.setattr(http, "client", explode)

        with pytest.raises(http.OfflineError):
            _ = http.get(_URL, ttl=60)


class TestOfflineErrorRedaction:
    def test_a_credential_never_reaches_the_message(self) -> None:
        # Libraries.io takes its key in the query string, and this message is
        # surfaced to users: as the offline_unavailable error for a fatal
        # lookup, and as the __cause__ of a source failure for an optional
        # one, where a traceback would print it.
        error = http.OfflineError(
            "https://libraries.io/api/pypi/requests?api_key=super-secret"
        )

        assert "super-secret" not in str(error)
        assert "super-secret" not in error.url
        assert error.url == "https://libraries.io/api/pypi/requests"

    def test_an_ordinary_url_is_reported_intact(self) -> None:
        error = http.OfflineError("https://pypi.org/pypi/requests/2.31.0/json")
        assert error.url == "https://pypi.org/pypi/requests/2.31.0/json"

    def test_a_credentialed_offline_miss_does_not_leak_through_the_source(
        self, cache_dir: Path
    ) -> None:
        # End to end: the enrichment source converts the offline miss into its
        # own error and chains the original, so the chain must be clean too.
        cache.configure(directory=cache_dir, offline=True)

        with pytest.raises(EnrichmentError) as caught:
            _ = stats.get_dependent_count("requests", api_key="super-secret")

        assert "super-secret" not in str(caught.value)
        assert "super-secret" not in str(caught.value.__cause__)


class TestRevalidationIsAlsoDeferred:
    def test_a_304_does_not_restamp_until_the_caller_keeps_it(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        # The stored body still has to satisfy the caller's decoder, which a
        # stricter parser could now reject. Blessing it on the 304 alone
        # would keep an unusable entry fresh for another full TTL.
        assert cache.settings().directory == cache_dir
        fake_http.reply(url="?d", json={"v": 1}, headers={"etag": "e"})
        http.keep(http.get(_URL + "?d", ttl=60))
        stored_at = frozen_clock[0]
        frozen_clock[0] += 61
        fake_http.reply(url="?d", status=304)

        again = http.get(_URL + "?d", ttl=60)

        assert again.provenance.freshness == "revalidated"
        entry = cache.load(cache.key_for("GET", _URL + "?d"))
        assert entry is not None
        assert entry.stored_at == stored_at

    def test_keeping_a_revalidated_result_restamps_it(
        self, fake_http: FakeTransport, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(url="?k", json={"v": 1}, headers={"etag": "e"})
        http.keep(http.get(_URL + "?k", ttl=60))
        frozen_clock[0] += 61
        fake_http.reply(url="?k", status=304)

        http.keep(http.get(_URL + "?k", ttl=60))

        third = http.get(_URL + "?k", ttl=60)
        assert third.provenance.freshness == "cached"
        assert len(fake_http.requests) == 2


class TestOfflineNeverBuildsAClient:
    @staticmethod
    def _explode() -> httpx.Client:
        msg = "no TLS available here"
        raise RuntimeError(msg)

    def test_an_uncached_get_refuses_before_construction(
        self, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache.configure(directory=cache_dir, offline=True)
        monkeypatch.setattr(http, "client", self._explode)

        with pytest.raises(http.OfflineError):
            _ = http.get(_URL)

    def test_a_post_refuses_before_construction(
        self, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # info/compare run OSV offline, and a broken TLS config must not turn
        # the defined offline outcome into a generic transport exception.
        cache.configure(directory=cache_dir, offline=True)
        monkeypatch.setattr(http, "client", self._explode)

        with pytest.raises(http.OfflineError):
            _ = http.post(_URL, json={"q": 1})

    def test_a_stale_revalidation_refuses_before_construction(
        self,
        fake_http: FakeTransport,
        cache_dir: Path,
        frozen_clock: list[float],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_http.reply(json={"v": 1})
        http.keep(http.get(_URL, ttl=60))
        frozen_clock[0] += 61
        cache.configure(directory=cache_dir, offline=True)
        monkeypatch.setattr(http, "client", self._explode)

        # A stale entry is still served offline, without a client.
        assert http.get(_URL, ttl=60).provenance.freshness == "cached"
