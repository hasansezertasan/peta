"""Recursive dependency-tree construction and ``deps --why`` path lookup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from packaging.markers import UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from peta.core import http
from peta.core.compatibility import supports_python
from peta.core.local import LocalTarget, PackageNotFoundError as LocalNotFound
from peta.core.models import DependencyNode, DependencyResolutionFailure
from peta.core.output import utc_now
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import resolve_package

if TYPE_CHECKING:
    from collections.abc import Iterable

    from peta.core.models import PackageInfo

__all__ = ["build_tree", "find_why"]

# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_UNRESOLVABLE = (LocalNotFound, RemoteNotFound, NetworkError, http.OfflineError)


def _canonical_extras(extras: Iterable[str]) -> tuple[str, ...]:
    """Return extras in their normalized, duplicate-free form.

    Returns:
        The sorted canonical extra names.
    """
    return tuple(sorted({canonicalize_name(extra) for extra in extras}))


def _requirement_key(req: Requirement) -> tuple[str, tuple[str, ...], str, str | None]:
    """Identify a requirement after its already-satisfied marker is removed.

    Returns:
        The normalized marker-free requirement identity.
    """
    return (
        canonicalize_name(req.name),
        _canonical_extras(req.extras),
        str(req.specifier),
        req.url,
    )


def _resolution_failure(
    exc: LocalNotFound | RemoteNotFound | NetworkError | http.OfflineError,
) -> DependencyResolutionFailure:
    # Offline is ``unavailable`` rather than ``failed``: nothing went wrong,
    # this dependency simply is not in the cache and peta was told not to ask.
    # The root resolution is not routed through here, so an offline root still
    # aborts the command instead of yielding a tree of unavailable nodes.
    if isinstance(exc, http.OfflineError):
        # No timestamp: this branch deliberately made no request, so dating it
        # would claim a retrieval that never happened.
        return DependencyResolutionFailure(
            source="pypi", state="unavailable", reason=str(exc), retrieved_at=None
        )
    if isinstance(exc, NetworkError):
        return DependencyResolutionFailure(
            source="pypi", state="failed", reason=str(exc), retrieved_at=utc_now()
        )
    # A not-found response means the provider completed the lookup and holds no
    # package data, which the output contract calls ``empty`` rather than
    # ``unavailable`` (reserved for a source that could not be configured).
    # Being a completed retrieval, it reports its origin like any other: a
    # PyPI 404 is always live, since only 200 responses are ever cached, and a
    # local miss has no retrieval to describe.
    local = isinstance(exc, LocalNotFound)
    return DependencyResolutionFailure(
        source="local" if local else "pypi",
        state="empty",
        reason=str(exc),
        retrieved_at=utc_now(),
        freshness=None if local else "live",
    )


def _resolve_cached(
    req: Requirement,
    cache: dict[str, PackageInfo | DependencyResolutionFailure],
    *,
    local: bool,
    remote: bool,
    target: LocalTarget | None,
) -> PackageInfo | DependencyResolutionFailure:
    """Resolve ``name`` via the cache, memoizing hits and failures alike.

    Returns:
        The resolved package or a structured lookup failure.
    """
    canon = f"{canonicalize_name(req.name)}:{req.specifier}:{req.url or ''}"
    if canon in cache:
        return cache[canon]
    result: PackageInfo | DependencyResolutionFailure
    if req.url is not None:
        result = DependencyResolutionFailure(
            source="direct-reference",
            state="unsupported",
            reason=f"Direct-reference dependency URLs are not supported: {req.url}",
            retrieved_at=None,
        )
        cache[canon] = result
        return result
    try:
        pkg = resolve_package(
            req.name,
            local=local,
            remote=remote,
            target=target,
            specifier=req.specifier,
            select_compatible=True,
        )
    except _UNRESOLVABLE as exc:
        result = _resolution_failure(exc)
    else:
        result = pkg
    cache[canon] = result
    return result


def _marker_satisfied(
    req: Requirement, marker_environment: dict[str, str] | None, extras: tuple[str, ...]
) -> bool:
    """Whether a requirement's environment marker holds for selected extras.

    When no extra is selected, evaluates with ``extra=""`` so optional
    dependencies resolve to unsatisfied rather than raising
    ``UndefinedEnvironmentName``. Any other undefined marker variable is likewise
    treated as unsatisfied.

    Returns:
        ``True`` if there is no marker or the marker is satisfied.
    """
    if req.marker is None:
        return True
    try:
        # bool(): packaging is unstubbed in the isolated prek mypy env, where
        # Marker.evaluate is seen as returning Any.
        environment = {"extra": ""}
        if marker_environment is not None:
            environment.update(marker_environment)
        selected_extras = extras or ("",)
        return any(
            bool(req.marker.evaluate({**environment, "extra": extra}))
            for extra in selected_extras
        )
    except UndefinedEnvironmentName:
        return False


def _kept_requirements(
    pkg: PackageInfo, marker_environment: dict[str, str] | None, extras: tuple[str, ...]
) -> list[Requirement]:
    """Parse a package's ``requires_dist`` entries, dropping unmet markers.

    Malformed entries (``InvalidRequirement``) are skipped so one bad transitive
    ``requires_dist`` string cannot abort the whole tree — only the root
    resolution is allowed to fail.

    Returns:
        The requirements whose environment marker (if any) is satisfied.
    """
    kept: list[Requirement] = []
    seen: set[tuple[str, tuple[str, ...], str, str | None]] = set()
    for raw in pkg.dependencies:
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        if not _marker_satisfied(req, marker_environment, extras):
            continue
        key = _requirement_key(req)
        if key not in seen:
            seen.add(key)
            kept.append(req)
    return kept


def _new_requirements(
    pkg: PackageInfo,
    marker_environment: dict[str, str] | None,
    extras: tuple[str, ...],
    previous_extras: frozenset[str] | None,
) -> list[Requirement]:
    """Return requirements newly activated since an earlier path expansion.

    Returns:
        All active requirements for a new node, or only the newly active ones
        when re-entering an ancestor with additional extras.
    """
    requirements = _kept_requirements(pkg, marker_environment, extras)
    if previous_extras is None:
        return requirements
    previous = _kept_requirements(
        pkg, marker_environment, tuple(sorted(previous_extras))
    )
    previous_keys = {_requirement_key(req) for req in previous}
    return [req for req in requirements if _requirement_key(req) not in previous_keys]


def _conflict_node(
    req: Requirement, child_pkg: PackageInfo, target: LocalTarget | None
) -> DependencyNode | None:
    allows_prereleases = not req.specifier or req.specifier.prereleases is True
    spec_ok = req.specifier.contains(child_pkg.version, prereleases=allows_prereleases)
    target_ok = supports_python(
        child_pkg, target.marker_environment if target is not None else None
    )
    if spec_ok and target_ok:
        return None
    return DependencyNode(
        name=req.name,
        version_spec=str(req.specifier),
        selected_version=child_pkg.version,
        state="conflicting",
        conflict_reason="version" if not spec_ok else "target",
        source=child_pkg.source,
        retrieved_at=child_pkg.retrieved_at,
        freshness=child_pkg.freshness,
    )


def _depth_limited_node(
    req: Requirement,
    child_pkg: PackageInfo,
    target: LocalTarget | None,
    extras: tuple[str, ...],
    previous_extras: frozenset[str] | None,
) -> DependencyNode:
    env = target.marker_environment if target else None
    has_active_deps = bool(_new_requirements(child_pkg, env, extras, previous_extras))
    return DependencyNode(
        name=req.name,
        version_spec=str(req.specifier),
        selected_version=child_pkg.version,
        state="depth_limited" if has_active_deps else "satisfied",
        source=child_pkg.source,
        retrieved_at=child_pkg.retrieved_at,
        freshness=child_pkg.freshness,
    )


def _cycle_node(
    req: Requirement,
    path: dict[str, tuple[PackageInfo, frozenset[str]]],
    target: LocalTarget | None,
) -> DependencyNode | None:
    canon = canonicalize_name(req.name)
    entry = path.get(canon)
    if entry is None:
        return None
    package, expanded_extras = entry
    conflict = _conflict_node(req, package, target)
    if conflict is not None:
        return conflict
    if not set(_canonical_extras(req.extras)).issubset(expanded_extras):
        return None
    return DependencyNode(
        name=req.name,
        version_spec=str(req.specifier),
        selected_version=package.version,
        state="circular",
        source=package.source,
        retrieved_at=package.retrieved_at,
        freshness=package.freshness,
    )


def _child_node(
    req: Requirement,
    path: dict[str, tuple[PackageInfo, frozenset[str]]],
    cache: dict[str, PackageInfo | DependencyResolutionFailure],
    *,
    local: bool,
    remote: bool,
    target: LocalTarget | None,
    depth: int,
    max_depth: int,
) -> DependencyNode:
    """Build the child node for a single requirement, recursing if allowed.

    Returns:
        The child's dependency node (a leaf when circular, unresolvable, or
        past ``max_depth``).
    """
    version_spec = str(req.specifier)
    canon = canonicalize_name(req.name)
    cycle = _cycle_node(req, path, target)
    if cycle is not None:
        return cycle
    path_entry = path.get(canon)
    resolved = (
        path_entry[0]
        if path_entry is not None
        else _resolve_cached(req, cache, local=local, remote=remote, target=target)
    )
    if isinstance(resolved, DependencyResolutionFailure):
        return DependencyNode(
            name=req.name,
            version_spec=version_spec,
            state="unresolved",
            resolution_failure=resolved,
        )
    conflict = _conflict_node(req, resolved, target)
    if conflict is not None:
        return conflict
    child_pkg = resolved
    extras = _canonical_extras(req.extras)
    previous_extras = path_entry[1] if path_entry is not None else None
    expanded_extras = (previous_extras or frozenset()) | frozenset(extras)
    active_extras = tuple(sorted(expanded_extras))
    if depth >= max_depth:
        return _depth_limited_node(
            req, child_pkg, target, active_extras, previous_extras
        )
    children = _expand(
        child_pkg,
        path,
        cache,
        local=local,
        remote=remote,
        target=target,
        depth=depth + 1,
        max_depth=max_depth,
        extras=active_extras,
    )
    return DependencyNode(
        name=req.name,
        version_spec=version_spec,
        selected_version=child_pkg.version,
        children=children,
        source=child_pkg.source,
        retrieved_at=child_pkg.retrieved_at,
        freshness=child_pkg.freshness,
    )


def _expand(
    pkg: PackageInfo,
    path: dict[str, tuple[PackageInfo, frozenset[str]]],
    cache: dict[str, PackageInfo | DependencyResolutionFailure],
    *,
    local: bool,
    remote: bool,
    target: LocalTarget | None,
    depth: int,
    max_depth: int,
    extras: tuple[str, ...],
) -> list[DependencyNode]:
    """Build the dependency nodes for every kept requirement of ``pkg``.

    Returns:
        The child dependency nodes.
    """
    canon = canonicalize_name(pkg.name)
    path_entry = path.get(canon)
    previous_extras = path_entry[1] if path_entry is not None else None
    expanded_path = {**path, canon: (pkg, frozenset(extras))}
    return [
        _child_node(
            req,
            expanded_path,
            cache,
            local=local,
            remote=remote,
            target=target,
            depth=depth,
            max_depth=max_depth,
        )
        for req in _new_requirements(
            pkg, target.marker_environment if target else None, extras, previous_extras
        )
    ]


def build_tree(
    name: str,
    *,
    local: bool,
    remote: bool,
    target: LocalTarget | None = None,
    max_depth: int = 10,
    extras: tuple[str, ...] = (),
) -> DependencyNode:
    """Recursively resolve ``name`` and its dependency tree.

    Only the root resolution can raise (propagated from
    :func:`peta.core.resolve.resolve_package`); unresolvable transitive
    dependencies become leaf nodes with ``selected_version=None`` instead.

    Returns:
        The root :class:`DependencyNode`, with children expanded recursively.
    """
    root_pkg = resolve_package(
        name, local=local, remote=remote, target=target, select_compatible=True
    )
    extras = _canonical_extras(extras)
    canon = canonicalize_name(root_pkg.name)
    cache: dict[str, PackageInfo | DependencyResolutionFailure] = {canon: root_pkg}
    target_compatible = supports_python(
        root_pkg, target.marker_environment if target is not None else None
    )
    children = (
        _expand(
            root_pkg,
            {},
            cache,
            local=local,
            remote=remote,
            target=target,
            depth=1,
            max_depth=max_depth,
            extras=extras,
        )
        if target_compatible
        else []
    )
    return DependencyNode(
        name=root_pkg.name,
        version_spec="",
        selected_version=root_pkg.version,
        state="satisfied" if target_compatible else "conflicting",
        conflict_reason=None if target_compatible else "target",
        children=children,
        source=root_pkg.source,
        retrieved_at=root_pkg.retrieved_at,
        freshness=root_pkg.freshness,
    )


def _collect_why(
    node: DependencyNode, canon_target: str, trail: list[str], paths: list[list[str]]
) -> None:
    for child in node.children:
        new_trail = [*trail, child.name]
        if canonicalize_name(child.name) == canon_target:
            paths.append(new_trail)
        else:
            _collect_why(child, canon_target, new_trail, paths)


def find_why(root: DependencyNode, target: str) -> list[list[str]]:
    """Find every root-to-``target`` path in the dependency tree.

    Returns:
        A list of name paths (each starting with ``root.name``); empty if
        ``target`` is not present anywhere in the tree.
    """
    canon_target = canonicalize_name(target)
    paths: list[list[str]] = []
    _collect_why(root, canon_target, [root.name], paths)
    return paths
