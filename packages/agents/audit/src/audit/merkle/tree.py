"""Merkle tree index over chain entries (audit v0.2 Task 5, Q2).

A per-chain binary Merkle tree over the entry hashes — an **indexing layer on top of** the
existing hash chain (it does not replace it). The Merkle root commits to the whole chain in
one hash, and membership proofs (Task 6) let a verifier confirm "entry X is in chain Y at
position Z" in O(log n) instead of an O(n) sequential walk. Pure + deterministic; read-only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

#: The Merkle root of an empty chain (sha256 of the empty string).
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MerkleTree:
    leaves: tuple[str, ...]
    #: levels[0] == leaves; each higher level halves; levels[-1] == [root] (non-empty tree).
    levels: tuple[tuple[str, ...], ...]

    @property
    def root(self) -> str:
        if not self.leaves:
            return EMPTY_ROOT
        return self.levels[-1][0]

    @property
    def depth(self) -> int:
        return len(self.levels)


def build_merkle_tree(leaf_hashes: Sequence[str]) -> MerkleTree:
    """Build the Merkle tree over ``leaf_hashes`` (the chain's entry hashes). An odd node at a
    level is paired with itself (the standard duplicate-last convention)."""
    if not leaf_hashes:
        return MerkleTree(leaves=(), levels=())
    levels: list[tuple[str, ...]] = [tuple(leaf_hashes)]
    current = list(leaf_hashes)
    while len(current) > 1:
        nxt: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(_hash_pair(left, right))
        levels.append(tuple(nxt))
        current = nxt
    return MerkleTree(leaves=tuple(leaf_hashes), levels=tuple(levels))


def merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Convenience: the Merkle root over ``leaf_hashes`` (``EMPTY_ROOT`` if empty)."""
    return build_merkle_tree(leaf_hashes).root
