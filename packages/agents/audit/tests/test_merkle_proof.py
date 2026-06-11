"""audit v0.2 Task 6 — Merkle membership proof tests (Q2)."""

from __future__ import annotations

import hashlib

import pytest
from audit.merkle.proof import MerkleProof, generate_proof, verify_proof
from audit.merkle.tree import build_merkle_tree


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_proof_verifies_for_every_leaf() -> None:
    leaves = [_h(x) for x in "abcd"]
    tree = build_merkle_tree(leaves)
    for i in range(len(leaves)):
        assert verify_proof(generate_proof(tree, i)) is True


def test_single_leaf_proof() -> None:
    tree = build_merkle_tree([_h("only")])
    proof = generate_proof(tree, 0)
    assert proof.steps == () and verify_proof(proof) is True


def test_odd_leaf_count_proof() -> None:
    leaves = [_h(x) for x in "abcde"]
    tree = build_merkle_tree(leaves)
    for i in range(len(leaves)):
        assert verify_proof(generate_proof(tree, i)) is True


def test_proof_carries_position() -> None:
    tree = build_merkle_tree([_h(x) for x in "abcd"])
    proof = generate_proof(tree, 2)
    assert proof.leaf_index == 2 and proof.leaf_hash == _h("c")
    assert proof.root == tree.root


def test_tampered_leaf_fails() -> None:
    tree = build_merkle_tree([_h(x) for x in "abcd"])
    proof = generate_proof(tree, 1)
    forged = MerkleProof(leaf_hash=_h("evil"), leaf_index=1, steps=proof.steps, root=proof.root)
    assert verify_proof(forged) is False


def test_wrong_root_fails() -> None:
    tree = build_merkle_tree([_h(x) for x in "abcd"])
    proof = generate_proof(tree, 0)
    forged = MerkleProof(leaf_hash=proof.leaf_hash, leaf_index=0, steps=proof.steps, root="0" * 64)
    assert verify_proof(forged) is False


def test_tampered_sibling_fails() -> None:
    from audit.merkle.proof import ProofStep

    tree = build_merkle_tree([_h(x) for x in "abcd"])
    proof = generate_proof(tree, 0)
    bad_steps = (ProofStep(sibling="0" * 64, sibling_is_right=True), *proof.steps[1:])
    forged = MerkleProof(proof.leaf_hash, 0, bad_steps, proof.root)
    assert verify_proof(forged) is False


def test_out_of_range_raises() -> None:
    tree = build_merkle_tree([_h("a")])
    with pytest.raises(IndexError):
        generate_proof(tree, 5)


def test_proof_log_depth() -> None:
    # 8 leaves -> 3 proof steps (log2 8).
    tree = build_merkle_tree([_h(str(i)) for i in range(8)])
    assert len(generate_proof(tree, 3).steps) == 3
