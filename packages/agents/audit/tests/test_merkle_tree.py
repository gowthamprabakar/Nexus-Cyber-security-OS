"""audit v0.2 Task 5 — Merkle tree index tests (Q2)."""

from __future__ import annotations

import hashlib

from audit.merkle.tree import EMPTY_ROOT, build_merkle_tree, merkle_root


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _pair(a: str, b: str) -> str:
    return hashlib.sha256((a + b).encode()).hexdigest()


def test_empty_tree_root() -> None:
    tree = build_merkle_tree([])
    assert tree.root == EMPTY_ROOT and tree.leaves == ()


def test_single_leaf_root_is_leaf() -> None:
    leaf = _h("entry0")
    assert build_merkle_tree([leaf]).root == leaf


def test_two_leaves() -> None:
    a, b = _h("a"), _h("b")
    assert build_merkle_tree([a, b]).root == _pair(a, b)


def test_odd_leaves_duplicate_last() -> None:
    a, b, c = _h("a"), _h("b"), _h("c")
    # level1 = [pair(a,b), pair(c,c)]; root = pair(of those)
    expected = _pair(_pair(a, b), _pair(c, c))
    assert build_merkle_tree([a, b, c]).root == expected


def test_four_leaves_depth() -> None:
    leaves = [_h(x) for x in "abcd"]
    tree = build_merkle_tree(leaves)
    assert tree.depth == 3  # leaves, pairs, root
    assert len(tree.levels[-1]) == 1


def test_deterministic() -> None:
    leaves = [_h(x) for x in "abcde"]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_root_changes_with_leaves() -> None:
    base = [_h(x) for x in "abc"]
    tampered = [_h(x) for x in "abx"]
    assert merkle_root(base) != merkle_root(tampered)


def test_order_matters() -> None:
    a, b = _h("a"), _h("b")
    assert merkle_root([a, b]) != merkle_root([b, a])


def test_merkle_root_empty() -> None:
    assert merkle_root([]) == EMPTY_ROOT
