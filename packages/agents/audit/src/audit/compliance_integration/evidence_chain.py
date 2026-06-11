"""F.6 chain proofs for compliance evidence bundles (audit v0.2 Task 11, Q4).

Ties each compliance finding back to its source **audit entry** with a Merkle membership proof
(Tasks 5-6): given the agent's audit chain and the correlation ids a compliance evidence entry
cites, generate a proof that each cited entry is in the chain, then attach the proofs to the
evidence entry. A downstream verifier (Task 12) re-checks them against the committed root.

All code lives in the audit package — ``attach_proofs_to_evidence`` returns a **new** dict, so
the compliance package is not modified (no cross-agent edit). Read-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from audit.merkle.proof import MerkleProof, generate_proof
from audit.merkle.tree import build_merkle_tree
from audit.schemas import AuditEvent


@dataclass(frozen=True, slots=True)
class EvidenceChainProof:
    correlation_id: str
    leaf_index: int
    proof: MerkleProof
    chain_root: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "leaf_index": self.leaf_index,
            "chain_root": self.chain_root,
            "leaf_hash": self.proof.leaf_hash,
            "steps": [
                {"sibling": s.sibling, "sibling_is_right": s.sibling_is_right}
                for s in self.proof.steps
            ],
        }


def build_evidence_proofs(
    events: Sequence[AuditEvent], correlation_ids: Iterable[str]
) -> tuple[EvidenceChainProof, ...]:
    """Generate a Merkle membership proof for each cited correlation id present in ``events``.
    Unknown correlation ids are skipped (they are not in this chain)."""
    tree = build_merkle_tree([e.entry_hash for e in events])
    index_by_corr = {e.correlation_id: i for i, e in enumerate(events)}
    out: list[EvidenceChainProof] = []
    for corr in correlation_ids:
        idx = index_by_corr.get(corr)
        if idx is None:
            continue
        out.append(
            EvidenceChainProof(
                correlation_id=corr,
                leaf_index=idx,
                proof=generate_proof(tree, idx),
                chain_root=tree.root,
            )
        )
    return tuple(out)


def attach_proofs_to_evidence(
    evidence_entry: dict[str, Any], proofs: Sequence[EvidenceChainProof]
) -> dict[str, Any]:
    """Return a copy of a compliance evidence entry with the audit-chain proofs attached."""
    return {**evidence_entry, "audit_chain_proofs": [p.to_dict() for p in proofs]}
