"""Recursive dependency-tree construction and ``deps --why`` path lookup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import DependencyNode
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound
from peta.core.resolve import resolve_package

if TYPE_CHECKING:
    from peta.core.models import PackageInfo

__all__ = ["build_tree", "find_why"]


# Tuple constant (not an inline ``except (A, B)`` literal) so the ruff formatter
# cannot strip the parentheses into Python-2-only ``except A, B`` syntax.
_UNRESOLVABLE = (LocalNotFound, RemoteNotFound, NetworkError)


def _resolve_cached(
    name: str, cache: dict[str, PackageInfo | None], *, local: bool, remote: bool
) -> PackageInfo | None:
    """Resolve ``name`` via the cache, memoizing hits and failures alike.

    Returns:
        The resolved package, or ``None`` if it could not be resolved.
    """
    canon = canonicalize_name(name)
    if canon in cache:
        return cache[canon]
    try:
        pkg = resolve_package(name, local=local, remote=remote)
    except _UNRESOLVABLE:
        pkg = None
    cache[canon] = pkg
    return pkg


def _kept_requirements(pkg: PackageInfo) -> list[Requirement]:
    """Parse a package's ``requires_dist`` entries, dropping unmet markers.

    Returns:
        The requirements whose environment marker (if any) is satisfied.
    """
    kept: list[Requirement] = []
    for raw in pkg.dependencies:
        req = Requirement(raw)
        if req.marker is None or req.marker.evaluate():
            kept.append(req)
    return kept


def _child_node(
    req: Requirement,
    path: frozenset[str],
    cache: dict[str, PackageInfo | None],
    *,
    local: bool,
    remote: bool,
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
    if canon in path:
        return DependencyNode(name=req.name, version_spec=version_spec, circular=True)
    child_pkg = _resolve_cached(req.name, cache, local=local, remote=remote)
    installed_version = child_pkg.version if child_pkg is not None else None
    if child_pkg is None or depth >= max_depth:
        return DependencyNode(
            name=req.name,
            version_spec=version_spec,
            installed_version=installed_version,
        )
    children = _expand(
        child_pkg,
        path | {canon},
        cache,
        local=local,
        remote=remote,
        depth=depth + 1,
        max_depth=max_depth,
    )
    return DependencyNode(
        name=req.name,
        version_spec=version_spec,
        installed_version=installed_version,
        children=children,
    )


def _expand(
    pkg: PackageInfo,
    path: frozenset[str],
    cache: dict[str, PackageInfo | None],
    *,
    local: bool,
    remote: bool,
    depth: int,
    max_depth: int,
) -> list[DependencyNode]:
    """Build the dependency nodes for every kept requirement of ``pkg``.

    Returns:
        The child dependency nodes.
    """
    return [
        _child_node(
            req,
            path,
            cache,
            local=local,
            remote=remote,
            depth=depth,
            max_depth=max_depth,
        )
        for req in _kept_requirements(pkg)
    ]


def build_tree(
    name: str, *, local: bool, remote: bool, max_depth: int = 10
) -> DependencyNode:
    """Recursively resolve ``name`` and its dependency tree.

    Only the root resolution can raise (propagated from
    :func:`peta.core.resolve.resolve_package`); unresolvable transitive
    dependencies become leaf nodes with ``installed_version=None`` instead.

    Returns:
        The root :class:`DependencyNode`, with children expanded recursively.
    """
    root_pkg = resolve_package(name, local=local, remote=remote)
    canon = canonicalize_name(root_pkg.name)
    cache: dict[str, PackageInfo | None] = {canon: root_pkg}
    children = _expand(
        root_pkg,
        frozenset({canon}),
        cache,
        local=local,
        remote=remote,
        depth=1,
        max_depth=max_depth,
    )
    return DependencyNode(
        name=root_pkg.name,
        version_spec="",
        installed_version=root_pkg.version,
        children=children,
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
