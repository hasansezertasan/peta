"""Unit tests for bounded, order-preserving concurrent lookups."""

from __future__ import annotations

import threading
import time
from functools import partial

import pytest

from peta.core import concurrency
from peta.core.concurrency import gather

pytestmark = pytest.mark.unit


def _identity(value: int) -> int:
    return value


class TestOrdering:
    def test_results_follow_the_input_order(self) -> None:
        assert gather([partial(_identity, n) for n in range(5)]) == [0, 1, 2, 3, 4]

    def test_completion_order_does_not_change_the_result_order(self) -> None:
        # The enrichment merge is first-writer-wins by provider order, so a
        # conflict is resolved by which source was consulted first. If a slow
        # source could overtake a fast one, that resolution would become a
        # race.
        def slow() -> str:
            time.sleep(0.05)
            return "first"

        assert gather([slow, lambda: "second"]) == ["first", "second"]

    def test_an_empty_list_yields_nothing(self) -> None:
        assert gather([]) == []

    def test_a_single_task_runs_without_a_pool(self) -> None:
        # Threading one task would cost a pool for no overlap, and would put a
        # worker thread in the middle of any traceback.
        caller = threading.current_thread()
        observed: list[threading.Thread] = []

        _ = gather([lambda: observed.append(threading.current_thread())])

        assert observed == [caller]


class TestConcurrency:
    def test_tasks_actually_overlap(self) -> None:
        # Without this, everything else here would pass over a serial loop.
        started = threading.Barrier(3, timeout=5)

        def wait_for_the_others() -> int:
            return started.wait()

        # A barrier of three can only be cleared if all three are in flight.
        assert sorted(gather([wait_for_the_others] * 3)) == [0, 1, 2]

    def test_no_more_than_the_bound_run_at_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(concurrency, "MAX_WORKERS", 2)
        lock = threading.Lock()
        live = 0
        peak = 0

        def observe() -> None:
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            time.sleep(0.02)
            with lock:
                live -= 1

        _ = gather([observe] * 8)

        assert peak <= 2


class TestFailures:
    def test_a_failing_task_propagates(self) -> None:
        def explode() -> int:
            msg = "no"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="no"):
            _ = gather([partial(_identity, 1), explode])

    def test_the_first_task_s_error_wins_not_the_first_to_fail(self) -> None:
        # Results are read in input order, so error reporting matches what a
        # serial loop would have produced: the earliest task's failure, even
        # though a later one failed sooner.
        def slow_failure() -> int:
            time.sleep(0.05)
            msg = "earlier task"
            raise RuntimeError(msg)

        def fast_failure() -> int:
            msg = "later task"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="earlier task"):
            _ = gather([slow_failure, fast_failure])
