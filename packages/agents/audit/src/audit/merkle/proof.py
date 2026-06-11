"""Merkle membership proofs (audit v0.2 Task 6, Q2).

Generates + verifies a Merkle **membership proof** — "entry X is in chain Y at position Z" —
from the Task-5 tree. A proof is the list of sibling hashes from the leaf up to the root; a
verifier recomputes the root from the leaf + siblings in O(log n) and compares it to the
committed root. Pure + deterministic; read-only. Consumed by the compliance-evidence
integration (M6).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from audit.merkle.tree import MerkleTree


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProofStep:
    sibling: str
    sibling_is_right: bool  # True if the sibling sits to the right of the running hash


@dataclass(frozen=True, slots=True)
class MerkleProof:
    leaf_hash: str
    leaf_index: int
    steps: tuple[ProofStep, ...]
    root: str


def generate_proof(tree: MerkleTree, leaf_index: int) -> MerkleProof:
    """Build a membership proof for the leaf at ``leaf_index``."""
    if not (0 <= leaf_index < len(tree.leaves)):
        raise IndexError(f"leaf_index {leaf_index} out of range (0..{len(tree.leaves) - 1})")
    idx = leaf_index
    steps: list[ProofStep] = []
    for level in tree.levels[:-1]:  # every level except the root
        if idx % 2 == 0:
            sib_idx = idx + 1 if idx + 1 < len(level) else idx  # odd node pairs with itself
            steps.append(ProofStep(sibling=level[sib_idx], sibling_is_right=True))
        else:
            steps.append(ProofStep(sibling=level[idx - 1], sibling_is_right=False))
        idx //= 2
    return MerkleProof(
        leaf_hash=tree.leaves[leaf_index],
        leaf_index=leaf_index,
        steps=tuple(steps),
        root=tree.root,
    )


def verify_proof(proof: MerkleProof) -> bool:
    """Recompute the root from the leaf + sibling steps; `True` iff it matches the proof root."""
    running = proof.leaf_hash
    for step in proof.steps:
        running = (
            _hash_pair(running, step.sibling)
            if step.sibling_is_right
            else _hash_pair(step.sibling, running)
        )
    return running == proof.root
