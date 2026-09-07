"""Unit tests for the on-disk response cache and its settings."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, get_args

import pytest

from peta.core import cache, http

if TYPE_CHECKING:
    from tests.transport import FakeTransport

pytestmark = pytest.mark.unit

_URL = "https://pypi.org/pypi/requests/json"


def test_freshness_values_match_the_alias() -> None:
    # The runtime set exists to check values an annotation cannot; it is only
    # useful while it says exactly what the alias says.
    assert set(get_args(cache.Freshness.__value__)) == cache.FRESHNESS_VALUES


class TestKeys:
    def test_the_same_request_derives_the_same_key(self) -> None:
        assert cache.key_for("GET", _URL) == cache.key_for("GET", _URL)

    def test_method_is_part_of_the_key(self) -> None:
        assert cache.key_for("GET", _URL) != cache.key_for("POST", _URL)

    def test_method_case_does_not_change_the_key(self) -> None:
        assert cache.key_for("get", _URL) == cache.key_for("GET", _URL)

    def test_different_urls_derive_different_keys(self) -> None:
        assert cache.key_for("GET", _URL) != cache.key_for("GET", _URL + "x")

    def test_the_key_is_a_usable_file_name(self) -> None:
        key = cache.key_for("GET", "https://x.invalid/a b?c=/d")
        assert key.isalnum()

    @pytest.mark.parametrize(
        "name", ["api_key", "apikey", "token", "access_token", "secret", "password"]
    )
    def test_credential_parameters_do_not_reach_the_key(self, name: str) -> None:
        # Two users with different keys ask the same question and must share
        # one entry; more importantly the secret must not survive into a
        # filename that outlives the process.
        base = "https://libraries.io/api/pypi/requests"
        mine = cache.key_for("GET", f"{base}?{name}=mine")
        yours = cache.key_for("GET", f"{base}?{name}=yours")
        assert mine == yours == cache.key_for("GET", base)

    def test_ordinary_parameters_still_distinguish_requests(self) -> None:
        base = "https://pypistats.org/api/packages/requests/recent"
        assert cache.key_for("GET", f"{base}?period=day") != cache.key_for(
            "GET", f"{base}?period=month"
        )


class TestSettings:
    def test_defaults_apply_before_anything_is_configured(self) -> None:
        cache.reset()
        resolved = cache.settings()
        assert resolved.enabled
        assert not resolved.offline
        assert not resolved.refresh

    def test_configure_replaces_rather_than_accumulates(self, tmp_path: Path) -> None:
        cache.configure(directory=tmp_path, offline=True)
        cache.configure(directory=tmp_path, refresh=True)
        assert not cache.settings().offline
        assert cache.settings().refresh

    def test_an_explicit_directory_wins(self, tmp_path: Path) -> None:
        cache.configure(directory=tmp_path / "somewhere")
        assert cache.settings().directory == tmp_path / "somewhere"

    def test_the_env_var_overrides_the_platform_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("PETA_CACHE_DIR", str(tmp_path / "env"))
        assert cache.default_directory() == tmp_path / "env"

    def test_xdg_is_honoured_when_no_override_is_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("PETA_CACHE_DIR", raising=False)
        monkeypatch.setattr(cache.sys, "platform", "linux")
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        assert cache.default_directory() == tmp_path / "peta"

    def test_it_falls_back_under_the_home_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("PETA_CACHE_DIR", raising=False)
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.setattr(cache.sys, "platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert cache.default_directory() == tmp_path / ".cache" / "peta"

    def test_windows_uses_the_local_app_data_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("PETA_CACHE_DIR", raising=False)
        monkeypatch.setattr(cache.sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert cache.default_directory() == tmp_path / "peta" / "Cache"


class TestRoundTrip:
    def test_a_stored_entry_reads_back(self, cache_dir: Path) -> None:
        key = cache.key_for("GET", _URL)
        cache.store(key, url=_URL, status=200, body='{"a":1}', headers={})

        entry = cache.load(key)

        assert entry is not None
        assert entry.status == 200
        assert entry.body == '{"a":1}'
        assert cache_dir.exists()

    def test_a_missing_entry_is_a_miss(self, cache_dir: Path) -> None:
        assert cache.settings().directory == cache_dir
        assert cache.load(cache.key_for("GET", _URL)) is None

    def test_nothing_is_read_or_written_while_disabled(self, tmp_path: Path) -> None:
        cache.configure(directory=tmp_path, enabled=False)
        key = cache.key_for("GET", _URL)
        cache.store(key, url=_URL, status=200, body="{}", headers={})
        assert cache.load(key) is None

    def test_only_allowlisted_headers_are_kept(self, cache_dir: Path) -> None:
        # Whatever a source chooses to send must not be persisted wholesale:
        # a stored Set-Cookie would outlive the process in a plain file.
        key = cache.key_for("GET", _URL)
        cache.store(
            key,
            url=_URL,
            status=200,
            body="{}",
            headers={
                "ETag": 'W/"abc"',
                "Set-Cookie": "session=secret",
                "X-Ratelimit-Token": "leak",
                "Content-Type": "application/json",
            },
        )

        entry = cache.load(key)

        assert entry is not None
        assert set(entry.headers) == {"etag", "content-type"}
        assert "secret" not in (cache_dir / f"{key}.json").read_text()

    def test_the_stored_url_has_credentials_removed(self, cache_dir: Path) -> None:
        url = "https://libraries.io/api/pypi/requests?api_key=super-secret"
        key = cache.key_for("GET", url)

        cache.store(key, url=url, status=200, body="{}", headers={})

        written = (cache_dir / f"{key}.json").read_text()
        assert "super-secret" not in written
        assert "libraries.io/api/pypi/requests" in written

    def test_an_unwritable_directory_is_not_fatal(self, tmp_path: Path) -> None:
        # A read-only home or a full disk must not fail a command that already
        # has its answer.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        cache.configure(directory=blocker / "cache", enabled=True)

        cache.store("k", url=_URL, status=200, body="{}", headers={})

        assert cache.load("k") is None


class TestCorruption:
    @pytest.mark.parametrize(
        "contents",
        [
            "",
            "{",
            "null",
            "[]",
            '"a string"',
            '{"status": 200}',
            '{"status": "200", "body": "{}", "at": 1.0, "headers": {}}',
            '{"status": true, "body": "{}", "at": 1.0, "headers": {}}',
            '{"status": 200, "body": 5, "at": 1.0, "headers": {}}',
            '{"status": 200, "body": "{}", "at": "soon", "headers": {}}',
            '{"status": 200, "body": "{}", "at": true, "headers": {}}',
            '{"status": 200, "body": "{}", "at": 1.0, "headers": []}',
            '{"status": 200, "body": "{}", "at": 1.0, "headers": {"a": 1}}',
        ],
    )
    def test_a_damaged_entry_reads_as_a_miss(
        self, cache_dir: Path, contents: str
    ) -> None:
        # A cache is disposable. Anything unreadable — a truncated write, a
        # future format — must degrade to a refetch, never raise.
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "k.json").write_text(contents)

        assert cache.load("k") is None

    def test_a_damaged_entry_is_replaced_by_the_next_store(
        self, cache_dir: Path
    ) -> None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "k.json").write_text("{ truncated")

        cache.store("k", url=_URL, status=200, body='{"ok":true}', headers={})

        entry = cache.load("k")
        assert entry is not None
        assert entry.body == '{"ok":true}'

    def test_a_write_leaves_no_temporary_files_behind(self, cache_dir: Path) -> None:
        cache.store("k", url=_URL, status=200, body="{}", headers={})
        assert list(cache_dir.glob("*.tmp")) == []


class TestFreshness:
    def test_an_entry_is_fresh_inside_its_ttl(self, frozen_clock: list[float]) -> None:
        entry = cache.CachedResponse(200, "{}", {}, stored_at=frozen_clock[0])
        frozen_clock[0] += 59
        assert entry.is_fresh(60, frozen_clock[0])

    def test_an_entry_is_stale_once_the_ttl_elapses(
        self, frozen_clock: list[float]
    ) -> None:
        entry = cache.CachedResponse(200, "{}", {}, stored_at=frozen_clock[0])
        frozen_clock[0] += 60
        assert not entry.is_fresh(60, frozen_clock[0])

    def test_a_clock_that_moved_backwards_does_not_read_as_ancient(self) -> None:
        # A negative age would otherwise be compared against the TTL and, for
        # a large enough jump, could make a brand-new entry look expired.
        entry = cache.CachedResponse(200, "{}", {}, stored_at=1_000.0)
        assert entry.age(500.0) == 0
        assert entry.is_fresh(1, 500.0)

    def test_ttls_are_ordered_by_how_mutable_the_data_is(self) -> None:
        assert cache.IMMUTABLE > cache.DAILY > cache.LATEST


class TestValidators:
    def test_an_etag_becomes_a_conditional_header(self) -> None:
        entry = cache.CachedResponse(200, "{}", {"etag": 'W/"v1"'}, stored_at=0.0)
        assert entry.validators == {"if-none-match": 'W/"v1"'}

    def test_a_last_modified_becomes_a_conditional_header(self) -> None:
        stamp = "Wed, 21 Oct 2015 07:28:00 GMT"
        entry = cache.CachedResponse(200, "{}", {"last-modified": stamp}, stored_at=0.0)
        assert entry.validators == {"if-modified-since": stamp}

    def test_no_validator_means_no_conditional_headers(self) -> None:
        entry = cache.CachedResponse(200, "{}", {}, stored_at=0.0)
        assert entry.validators == {}


class TestTouch:
    def test_revalidating_restamps_without_changing_the_body(
        self, cache_dir: Path, frozen_clock: list[float]
    ) -> None:
        assert cache.settings().directory == cache_dir
        cache.store("k", url=_URL, status=200, body='{"v":1}', headers={"etag": "e"})
        stored = cache.load("k")
        assert stored is not None
        frozen_clock[0] += 10_000

        cache.touch("k", stored, url=_URL)

        again = cache.load("k")
        assert again is not None
        assert again.body == '{"v":1}'
        assert again.stored_at == frozen_clock[0]


class TestEndToEndThroughHttp:
    """The cache seen through :mod:`peta.core.http`, as the sources use it."""

    def test_a_second_identical_request_is_served_from_disk(
        self, fake_http: FakeTransport, cache_dir: Path
    ) -> None:
        assert cache.settings().directory == cache_dir
        fake_http.reply(json={"info": {}})

        first = http.get(_URL, ttl=60)
        http.keep(first)
        second = http.get(_URL, ttl=60)

        assert first.provenance.freshness == "live"
        assert second.provenance.freshness == "cached"
        # The point of the exercise: the source was asked exactly once.
        assert len(fake_http.requests) == 1
        assert second.response.json() == {"info": {}}


def test_a_cached_entry_is_valid_json_on_disk(cache_dir: Path) -> None:
    cache.store("k", url=_URL, status=200, body="{}", headers={"etag": "e"})
    payload = json.loads((cache_dir / "k.json").read_text())
    assert payload["status"] == 200
    assert payload["url"] == _URL


class TestWriteFailures:
    def test_a_failed_write_leaves_no_partial_file(
        self, cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The temporary file is created before the body is written, so a
        # failure midway must not leave it behind to accumulate forever.
        cache_dir.mkdir(parents=True, exist_ok=True)

        def explode(*_args: object, **_kwargs: object) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(cache.json, "dump", explode)

        cache.store("k", url=_URL, status=200, body="{}", headers={})

        assert list(cache_dir.glob("*.tmp")) == []
        assert cache.load("k") is None

    def test_windows_without_local_app_data_falls_through(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("PETA_CACHE_DIR", raising=False)
        monkeypatch.setattr(cache.sys, "platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))

        assert cache.default_directory() == tmp_path / "peta"


class TestPruning:
    def test_an_entry_past_the_max_age_is_deleted_on_the_next_write(
        self, cache_dir: Path
    ) -> None:
        # A TTL decides whether an entry may be served, not whether it is
        # kept. Without pruning, walking a dependency tree would leave every
        # file on disk for good, so the advertised lifetimes would bound
        # nothing at all.
        cache_dir.mkdir(parents=True, exist_ok=True)
        ancient = cache_dir / "ancient.json"
        ancient.write_text("{}")
        old = cache.now() - cache.MAX_AGE - 60
        os.utime(ancient, (old, old))

        cache.store("fresh", url=_URL, status=200, body="{}", headers={})

        assert not ancient.exists()
        assert (cache_dir / "fresh.json").exists()

    def test_an_entry_within_the_max_age_survives(self, cache_dir: Path) -> None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        recent = cache_dir / "recent.json"
        recent.write_text("{}")
        just_inside = cache.now() - cache.MAX_AGE + 3600
        os.utime(recent, (just_inside, just_inside))

        cache.store("fresh", url=_URL, status=200, body="{}", headers={})

        assert recent.exists()

    def test_pruning_ignores_files_it_does_not_own(self, cache_dir: Path) -> None:
        # Only peta's own entries are removed; anything else in the directory
        # is left alone rather than deleted on a user's behalf.
        cache_dir.mkdir(parents=True, exist_ok=True)
        stranger = cache_dir / "notes.txt"
        stranger.write_text("do not delete me")
        old = cache.now() - cache.MAX_AGE - 60
        os.utime(stranger, (old, old))

        cache.store("fresh", url=_URL, status=200, body="{}", headers={})

        assert stranger.exists()

    def test_the_longest_ttl_is_never_pruned_early(self) -> None:
        # Pruning must not discard an entry that could still have been served.
        assert cache.MAX_AGE >= cache.IMMUTABLE
