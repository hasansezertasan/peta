"""Unit tests for the recursive dependency tree builder."""

from unittest.mock import MagicMock, patch

import pytest

from peta.core.deptree import build_tree, find_why
from peta.core.local import PackageNotFoundError as LocalNotFound
from peta.core.models import DependencyNode, PackageInfo
from peta.core.remote import NetworkError

pytestmark = pytest.mark.unit


def _pkg(name: str, deps: list[str]) -> PackageInfo:
    return PackageInfo(name=name, version="1.0", source="local", dependencies=deps)


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
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["a"])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False)
        b_node = tree.children[0]
        assert b_node.name == "b"
        a_child = b_node.children[0]
        assert a_child.name == "a"
        assert a_child.circular is True
        assert a_child.children == []

    @patch("peta.core.deptree.resolve_package")
    def test_max_depth_truncates(self, m: MagicMock) -> None:
        pkgs = {"a": _pkg("a", ["b"]), "b": _pkg("b", ["c"]), "c": _pkg("c", [])}
        m.side_effect = lambda name, **_kw: pkgs[name]
        tree = build_tree("a", local=False, remote=False, max_depth=1)
        b_node = tree.children[0]
        assert b_node.name == "b"
        assert b_node.children == []

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
