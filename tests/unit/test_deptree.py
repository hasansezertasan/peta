"""Unit tests for the recursive dependency tree builder."""

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from peta.core import http
from peta.core.deptree import build_tree, find_why
from peta.core.local import LocalTarget, PackageNotFoundError as LocalNotFound
from peta.core.models import DependencyNode, PackageInfo
from peta.core.remote import NetworkError, PackageNotFoundError as RemoteNotFound

pytestmark = pytest.mark.unit


def _pkg(name: str, deps: list[str]) -> PackageInfo:
    return PackageInfo(name=name, version="1.0", source="local", dependencies=deps)


def _raise(exc: Exception) -> PackageInfo:
    """Re-raise ``exc``, since a lambda cannot contain a raise statement."""
    raise exc


class TestBuildTreeConflicts:
    @patch("peta.core.deptree.resolve_package")
    def test_running_python_incompatible_root_is_conflicting(
        self, m: MagicMock
    ) -> None:
        m.return_value = replace(_pkg("root", ["child"]), python_requires=">=999")

        tree = build_tree("root", local=False, remote=True)

        assert tree.state == "conflicting"
        assert tree.conflict_reason == "target"
        assert tree.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_target_incompatible_root_is_conflicting(self, m: MagicMock) -> None:
        m.return_value = replace(_pkg("root", ["child"]), python_requires=">=4")
        target = LocalTarget(
            paths=None,
            interpreter=None,
            marker_environment={"python_full_version": "3.12.0"},
        )

        tree = build_tree("root", local=False, remote=True, target=target)

        assert tree.state == "conflicting"
        assert tree.conflict_reason == "target"
        assert tree.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_invalid_requires_python_does_not_crash(self, m: MagicMock) -> None:
        m.return_value = replace(
            _pkg("root", ["child"]), python_requires="invalid specifier !!!"
        )
        target = LocalTarget(
            paths=None,
            interpreter=None,
            marker_environment={"python_full_version": "3.12.0"},
        )
        tree = build_tree("root", local=False, remote=True, target=target)
        assert tree.state == "conflicting"
        assert tree.conflict_reason == "target"

    @patch("peta.core.deptree.resolve_package")
    def test_leaf_at_max_depth_is_not_depth_limited(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False, max_depth=1)
        assert tree.children[0].name == "b"
        assert tree.children[0].state == "satisfied"

    @patch("peta.core.deptree.resolve_package")
    def test_non_leaf_at_max_depth_is_depth_limited(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["c"]), "c": _pkg("c", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False, max_depth=1)
        assert tree.children[0].name == "b"
        assert tree.children[0].state == "depth_limited"

    @patch("peta.core.deptree.resolve_package")
    def test_child_conflict_reason_version_vs_target(self, m: MagicMock) -> None:
        pkgs = {
            "a": _pkg("a", ["b>=2.0", "c"]),
            "b": replace(_pkg("b", []), version="1.0"),
            "c": replace(_pkg("c", []), python_requires=">=3.14"),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        target = LocalTarget(
            paths=None,
            interpreter=None,
            marker_environment={"python_full_version": "3.12.0"},
        )
        tree = build_tree("a", local=False, remote=False, target=target)
        assert tree.children[0].name == "b"
        assert tree.children[0].state == "conflicting"
        assert tree.children[0].conflict_reason == "version"
        assert tree.children[1].name == "c"
        assert tree.children[1].state == "conflicting"
        assert tree.children[1].conflict_reason == "target"

    @patch("peta.core.deptree.resolve_package")
    def test_ordinary_requirement_rejects_selected_prerelease(
        self, m: MagicMock
    ) -> None:
        pkgs = {
            "root": _pkg("root", ["child<2"]),
            "child": replace(_pkg("child", ["must-not-expand"]), version="1.9rc1"),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        child = build_tree("root", local=True, remote=False).children[0]

        assert child.state == "conflicting"
        assert child.conflict_reason == "version"
        assert child.children == []


class TestBuildTree:
    @patch("peta.core.deptree.resolve_package")
    def test_linear_chain(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["c"]), "c": _pkg("c", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        assert tree.name == "a"
        assert tree.children[0].name == "b"
        assert tree.children[0].children[0].name == "c"
        assert tree.children[0].children[0].children == []

    @patch("peta.core.deptree.resolve_package")
    def test_skips_malformed_and_extra_gated_requirements(self, m: MagicMock) -> None:
        # A malformed requires_dist string (InvalidRequirement) and an
        # optional extra-gated dep must be skipped, never crash the tree.
        pkgs = {
            "a": _pkg("a", ["b", "!!!broken syntax!!!", 'x; extra == "test"']),
            "b": _pkg("b", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        assert [c.name for c in tree.children] == ["b"]

    @patch("peta.core.deptree.resolve_package")
    def test_diamond_resolves_shared_dep_once(self, m: MagicMock) -> None:
        pkgs = {
            "a": _pkg("a", ["b", "c"]),
            "b": _pkg("b", ["d"]),
            "c": _pkg("c", ["d"]),
            "d": _pkg("d", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        assert {c.name for c in tree.children} == {"b", "c"}
        d_names = [
            grandchild.name for child in tree.children for grandchild in child.children
        ]
        assert d_names == ["d", "d"]
        # root + b + c + d resolved once each = 4 calls (not 5).
        assert m.call_count == 4

    @patch("peta.core.deptree.resolve_package")
    def test_cycle_marks_circular_and_stops(self, m: MagicMock) -> None:
        pkgs = {
            "a": replace(
                _pkg("a", ["b"]),
                source="pypi",
                retrieved_at="2026-09-21T00:00:00Z",
                freshness="live",
            ),
            "b": _pkg("b", ["a"]),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        b_node = tree.children[0]
        assert b_node.name == "b"
        a_child = b_node.children[0]
        assert a_child.name == "a"
        assert a_child.circular is True
        assert a_child.selected_version == "1.0"
        assert a_child.source == "pypi"
        assert a_child.retrieved_at == "2026-09-21T00:00:00Z"
        assert a_child.freshness == "live"
        assert a_child.children == []


class TestBuildTreeExpansion:
    @patch("peta.core.deptree.resolve_package")
    def test_cycle_compares_canonical_extra_names(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["a[foo_bar]"])}
        m.side_effect = lambda name, **_kw: pkgs[name]

        nested_a = (
            build_tree("a", local=True, remote=False, extras=("foo-bar",))
            .children[0]
            .children[0]
        )

        assert nested_a.state == "circular"
        assert nested_a.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_cycle_expands_newly_activated_extras_once(self, m: MagicMock) -> None:
        pkgs = {
            "a": _pkg("a", ["b", 'c; extra == "feature"']),
            "b": _pkg("b", ["a[feature]"]),
            "c": _pkg("c", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        nested_a = build_tree("a", local=True, remote=False).children[0].children[0]

        assert nested_a.name == "a"
        assert nested_a.state == "satisfied"
        assert [child.name for child in nested_a.children] == ["b", "c"]
        assert nested_a.children[0].state == "circular"

    @patch("peta.core.deptree.resolve_package")
    def test_incompatible_cycle_edge_is_a_version_conflict(self, m: MagicMock) -> None:
        pkgs = {"a": replace(_pkg("a", ["b"]), version="2.0"), "b": _pkg("b", ["a<2"])}
        m.side_effect = lambda name, **_kw: pkgs[name]

        leaf = build_tree("a", local=False, remote=False).children[0].children[0]

        assert leaf.name == "a"
        assert leaf.selected_version == "2.0"
        assert leaf.state == "conflicting"
        assert leaf.conflict_reason == "version"

    @patch("peta.core.deptree.resolve_package")
    def test_max_depth_truncates(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["c"]), "c": _pkg("c", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False, max_depth=1)
        b_node = tree.children[0]
        assert b_node.name == "b"
        assert b_node.children == []
        assert b_node.state == "depth_limited"

    @patch("peta.core.deptree.resolve_package")
    def test_conflicting_selection_is_not_expanded(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b<2"]), "b": _pkg("b", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]

        child = build_tree("a", local=True, remote=False).children[0]

        assert child.selected_version == "1.0"
        assert child.state == "satisfied"

    @patch("peta.core.deptree.resolve_package")
    def test_unsatisfied_selection_is_marked_conflicting(self, m: MagicMock) -> None:
        pkgs = {
            "a": _pkg("a", ["b<2"]),
            "b": replace(_pkg("b", ["would-not-be-expanded"]), version="3.0"),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        child = build_tree("a", local=True, remote=False).children[0]

        assert child.selected_version == "3.0"
        assert child.state == "conflicting"
        assert child.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_unsatisfied_marker_skipped(self, m: MagicMock) -> None:
        pkgs = {
            "a": _pkg("a", ["b; extra == 'dev'", "c; python_version < '3.0'", "d"]),
            "d": _pkg("d", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        assert [c.name for c in tree.children] == ["d"]

    @patch("peta.core.deptree.resolve_package")
    def test_selected_extra_does_not_also_evaluate_base_extra(
        self, m: MagicMock
    ) -> None:
        pkgs = {
            "root": _pkg(
                "root", ['base; extra != "feature"', 'enabled; extra == "feature"']
            ),
            "enabled": _pkg("enabled", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        tree = build_tree("root", local=True, remote=False, extras=("feature",))

        assert [child.name for child in tree.children] == ["enabled"]

    @patch("peta.core.deptree.resolve_package")
    def test_multiple_extras_union_duplicate_requirements(self, m: MagicMock) -> None:
        pkgs = {
            "root": _pkg("root", ['child; extra == "docs"', 'child; extra == "dev"']),
            "child": _pkg("child", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        tree = build_tree("root", local=True, remote=False, extras=("docs", "dev"))

        assert [child.name for child in tree.children] == ["child"]
        assert m.call_count == 2

    @patch("peta.core.deptree.resolve_package")
    def test_python_override_updates_cpython_implementation_marker(
        self, m: MagicMock
    ) -> None:
        pkgs = {
            "a": _pkg("a", ['b; implementation_version < "3.13"']),
            "b": _pkg("b", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        target = LocalTarget.create(python_version="3.12")

        tree = build_tree("a", local=False, remote=False, target=target)

        assert [child.name for child in tree.children] == ["b"]

    @patch("peta.core.deptree.resolve_package")
    def test_root_extra_does_not_leak_to_transitive_packages(
        self, m: MagicMock
    ) -> None:
        pkgs = {
            "root": _pkg("root", ["child"]),
            "child": _pkg("child", ['leaked; extra == "feature"']),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        tree = build_tree("root", local=True, remote=False, extras=("feature",))

        assert tree.children[0].children == []

    @patch("peta.core.deptree.resolve_package")
    def test_requirement_extra_activates_only_its_child(self, m: MagicMock) -> None:
        pkgs = {
            "root": _pkg("root", ["child[feature]"]),
            "child": _pkg("child", ['enabled; extra == "feature"']),
            "enabled": _pkg("enabled", []),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]

        tree = build_tree("root", local=True, remote=False)

        assert [node.name for node in tree.children[0].children] == ["enabled"]

    @patch("peta.core.deptree.resolve_package")
    def test_target_incompatible_selection_is_conflicting(self, m: MagicMock) -> None:
        pkgs = {
            "root": _pkg("root", ["child"]),
            "child": replace(_pkg("child", []), python_requires=">=4"),
        }
        m.side_effect = lambda name, **_kw: pkgs[name]
        target = LocalTarget(
            paths=None,
            interpreter=None,
            marker_environment={"python_full_version": "3.12.0"},
        )

        child = build_tree("root", local=True, remote=False, target=target).children[0]

        assert child.state == "conflicting"
        assert child.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_unresolvable_transitive_dep_becomes_leaf(self, m: MagicMock) -> None:
        def resolver(name: str, **_kw: object) -> PackageInfo:
            if name == "a":
                return _pkg("a", ["missing"])
            raise LocalNotFound(name)

        m.side_effect = resolver
        tree = build_tree("a", local=False, remote=False)
        leaf = tree.children[0]
        assert leaf.name == "missing"
        assert leaf.installed_version is None
        assert leaf.children == []
        assert leaf.resolution_failure is not None
        # A not-found lookup is a source that answered with no data.
        assert leaf.resolution_failure.state == "empty"
        assert leaf.resolution_failure.source == "local"

    @patch("peta.core.deptree.resolve_package")
    def test_direct_reference_is_unresolved_without_name_lookup(
        self, m: MagicMock
    ) -> None:
        url = "https://example.invalid/child-1.0.whl"
        m.return_value = _pkg("root", [f"child @ {url}"])

        leaf = build_tree("root", local=True, remote=False).children[0]

        assert leaf.name == "child"
        assert leaf.state == "unresolved"
        assert leaf.selected_version is None
        assert leaf.resolution_failure is not None
        assert leaf.resolution_failure.source == "direct-reference"
        assert leaf.resolution_failure.state == "unsupported"
        assert url in leaf.resolution_failure.reason
        assert leaf.resolution_failure.retrieved_at is None
        m.assert_called_once_with(
            "root", local=True, remote=False, target=None, select_compatible=True
        )

    @patch("peta.core.deptree.resolve_package")
    def test_network_failure_is_preserved_on_leaf(self, m: MagicMock) -> None:
        def resolver(name: str, **_kw: object) -> PackageInfo:
            if name == "a":
                return _pkg("a", ["unreachable"])
            msg = "connection reset"
            raise NetworkError(msg)

        m.side_effect = resolver
        leaf = build_tree("a", local=False, remote=False).children[0]
        assert leaf.resolution_failure is not None
        assert leaf.resolution_failure.state == "failed"
        assert leaf.resolution_failure.source == "pypi"
        assert leaf.resolution_failure.reason == "Network error: connection reset"

    @patch("peta.core.deptree.resolve_package")
    def test_an_uncached_dep_is_unavailable_when_offline(self, m: MagicMock) -> None:
        # ``unavailable`` rather than ``failed``: nothing went wrong, this
        # dependency simply is not cached and peta was told not to ask. The
        # resolved part of the tree must survive.
        offline = http.OfflineError("https://pypi.org/pypi/b/json")
        m.side_effect = lambda name, **_kw: (
            _pkg("a", ["b"]) if name == "a" else _raise(offline)
        )
        tree = build_tree("a", local=False, remote=False)

        leaf = tree.children[0]
        assert leaf.installed_version is None
        assert leaf.resolution_failure is not None
        assert leaf.resolution_failure.state == "unavailable"
        assert leaf.resolution_failure.source == "pypi"
        assert "offline" in leaf.resolution_failure.reason

    @patch("peta.core.deptree.resolve_package")
    def test_an_offline_root_still_aborts(self, m: MagicMock) -> None:
        # The root is not routed through the per-dependency guard, so a tree
        # of entirely unavailable nodes is never produced.
        m.side_effect = http.OfflineError("https://pypi.org/pypi/a/json")
        with pytest.raises(http.OfflineError):
            _ = build_tree("a", local=False, remote=False)

    @patch("peta.core.deptree.resolve_package")
    def test_root_not_found_raises(self, m: MagicMock) -> None:
        m.side_effect = LocalNotFound("a")
        with pytest.raises(LocalNotFound):
            build_tree("a", local=False, remote=False)


class TestFindWhy:
    def _tree(self) -> DependencyNode:
        certifi = DependencyNode(name="certifi", version_spec="")
        requests = DependencyNode(
            name="requests", version_spec=">=2", children=[certifi]
        )
        urllib3 = DependencyNode(name="urllib3", version_spec="")
        return DependencyNode(
            name="flask", version_spec="", children=[requests, urllib3]
        )

    def test_single_path(self) -> None:
        paths = find_why(self._tree(), "certifi")
        assert paths == [["flask", "requests", "certifi"]]

    def test_multiple_paths(self) -> None:
        certifi = DependencyNode(name="certifi", version_spec="")
        a = DependencyNode(name="a", version_spec="", children=[certifi])
        b = DependencyNode(name="b", version_spec="", children=[certifi])
        root = DependencyNode(name="root", version_spec="", children=[a, b])
        paths = find_why(root, "certifi")
        assert sorted(paths) == [["root", "a", "certifi"], ["root", "b", "certifi"]]

    def test_not_present(self) -> None:
        assert find_why(self._tree(), "nope") == []

    def test_case_insensitive(self) -> None:
        paths = find_why(self._tree(), "Certifi")
        assert paths == [["flask", "requests", "certifi"]]


class TestFreshness:
    @patch("peta.core.deptree.resolve_package")
    def test_each_node_reports_where_its_metadata_came_from(self, m: MagicMock) -> None:
        # A tree can be assembled from a mix, so freshness is per node rather
        # than one figure for the whole command.
        served = replace(_pkg("b", []), freshness="cached")
        fetched = replace(_pkg("a", ["b"]), freshness="live")
        m.side_effect = lambda name, **_kw: fetched if name == "a" else served

        tree = build_tree("a", local=False, remote=False)

        assert tree.freshness == "live"
        assert tree.children[0].freshness == "cached"

    @patch("peta.core.deptree.resolve_package")
    def test_a_truncated_node_still_reports_its_origin(self, m: MagicMock) -> None:
        served = replace(_pkg("b", ["c"]), freshness="cached")
        m.side_effect = lambda name, **_kw: _pkg("a", ["b"]) if name == "a" else served

        tree = build_tree("a", local=False, remote=False, max_depth=1)

        assert tree.children[0].freshness == "cached"


class TestOfflineProvenance:
    @patch("peta.core.deptree.resolve_package")
    def test_an_offline_miss_claims_no_retrieval_time(self, m: MagicMock) -> None:
        # The branch deliberately makes no request, so dating it would claim a
        # retrieval that never happened.
        offline = http.OfflineError("https://pypi.org/pypi/b/json")
        m.side_effect = lambda name, **_kw: (
            _pkg("a", ["b"]) if name == "a" else _raise(offline)
        )

        tree = build_tree("a", local=False, remote=False)

        failure = tree.children[0].resolution_failure
        assert failure is not None
        assert failure.retrieved_at is None

    @patch("peta.core.deptree.resolve_package")
    def test_a_network_failure_still_records_when_it_happened(
        self, m: MagicMock
    ) -> None:
        # A request was made and failed, so there is a real moment to report.
        m.side_effect = lambda name, **_kw: (
            _pkg("a", ["b"]) if name == "a" else _raise(NetworkError("reset"))
        )

        tree = build_tree("a", local=False, remote=False)

        failure = tree.children[0].resolution_failure
        assert failure is not None
        assert failure.retrieved_at is not None


class TestEmptyResolutionProvenance:
    @patch("peta.core.deptree.resolve_package")
    def test_a_pypi_miss_reports_a_live_origin(self, m: MagicMock) -> None:
        # `empty` is a completed retrieval — PyPI was asked and holds nothing —
        # so it reports its origin like any other completed lookup. Always
        # live, since only 200 responses are ever cached.
        m.side_effect = lambda name, **_kw: (
            _pkg("a", ["b"]) if name == "a" else _raise(RemoteNotFound("b"))
        )

        tree = build_tree("a", local=False, remote=False)

        failure = tree.children[0].resolution_failure
        assert failure is not None
        assert failure.state == "empty"
        assert failure.freshness == "live"

    @patch("peta.core.deptree.resolve_package")
    def test_a_local_miss_has_no_origin_to_report(self, m: MagicMock) -> None:
        m.side_effect = lambda name, **_kw: (
            _pkg("a", ["b"]) if name == "a" else _raise(LocalNotFound("b"))
        )

        tree = build_tree("a", local=False, remote=False)

        failure = tree.children[0].resolution_failure
        assert failure is not None
        assert failure.state == "empty"
        assert failure.freshness is None
