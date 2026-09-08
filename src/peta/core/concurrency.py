"""Running independent lookups at the same time, without losing their order.

Peta's slow work is waiting on other people's servers. A package's three
enrichment sources have no dependency on each other, and neither do the two
packages of a comparison, yet each waited for the last: measured against the
live services, roughly 44% of a package's enrichment latency was one source
idling while another was queried.

Order is not incidental here. The enrichment merge is first-writer-wins by
provider order, so a conflict between two sources is resolved by which was
consulted first. Results must therefore come back in the order the caller
asked for them, whatever order they actually complete in.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__all__ = ["MAX_WORKERS", "gather"]

# A plain ``TypeVar`` rather than PEP 695 ``def gather[T]``: the isolated mypy
# and vulture environments this project runs under prek cannot parse the newer
# syntax, the same constraint that keeps ``TypeAliasType`` in use elsewhere
# instead of ``type`` statements.
_T = TypeVar("_T")


MAX_WORKERS = 8
"""How many lookups may be in flight from one :func:`gather` call.

Threads are not the scarce resource — sockets are — so the real bound on
concurrent requests is the connection limit on the shared client in
:mod:`peta.core.http`, which applies however many callers are running. This
number keeps any single fan-out from creating threads without limit, and is
set above peta's widest fan-out (three enrichment sources, two compared
packages) so the bound never shapes ordinary work.
"""


def gather(  # ruff: ignore[non-pep695-generic-function]
    tasks: Sequence[Callable[[], _T]],
) -> list[_T]:
    """Run independent tasks concurrently and return results in input order.

    Nothing is threaded for a single task, so the common case — one package,
    one source — costs no pool, no threads, and no change to a traceback.

    A task that raises propagates, and because results are consumed in input
    order the exception surfaced is the first task's, not the first to fail.
    That keeps error reporting identical to running them one after another.
    Tasks after a failing one still run, since they were already started;
    peta's callers treat that as a wasted request rather than a problem.

    Args:
        tasks: Callables to run. Each must be independent of the others'
            results, and safe to call from another thread.

    Returns:
        One result per task, in the order the tasks were given.
    """
    if len(tasks) <= 1:
        return [task() for task in tasks]
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(tasks))) as pool:
        # Everything is submitted before any result is read, so the tasks
        # overlap; reading the futures back in submission order is what keeps
        # the results aligned with the caller's list.
        futures = [pool.submit(task) for task in tasks]
        return [future.result() for future in futures]
