"""Evidence chain verification API (audit v0.2 Task 12, Q4).

The downstream side of the Task-11 integration: reconstruct the audit-chain proofs attached to
a compliance evidence entry and verify each one against the committed Merkle root. Consumed by
compliance's evidence export + audit-ready report generation so a third party can confirm every
cited finding is provably in the agent's audit chain. Read-only.

Pass ``expected_root`` to bind verification to a known chain root — without it a proof only
proves internal consistency (leaf + steps recompute its own ``root``); with it, a proof whose
root differs from the trusted chain root is rejected.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from audit.merkle.proof import MerkleProof, ProofStep, verify_proof


@dataclass(frozen=True, slots=True)
class ProofVerification:
    correlation_id: str
    valid: bool


@dataclass(frozen=True, slots=True)
class EvidenceVerificationResult:
    all_valid: bool
    proofs_checked: int
    results: tuple[ProofVerification, ...]


def _proof_from_dict(data: dict[str, Any]) -> MerkleProof:
    steps = tuple(
        ProofStep(sibling=s["sibling"], sibling_is_right=s["sibling_is_right"])
        for s in data["steps"]
    )
    return MerkleProof(
        leaf_hash=data["leaf_hash"],
        leaf_index=data["leaf_index"],
        steps=steps,
        root=data["chain_root"],
    )


def verify_evidence_proofs(
    evidence_entry: dict[str, Any], *, expected_root: str | None = None
) -> EvidenceVerificationResult:
    """Verify every audit-chain proof attached to ``evidence_entry``. An entry with no attached
    proofs verifies vacuously (``all_valid`` True, ``proofs_checked`` 0) so a consumer can
    distinguish "verified" from "no proofs present"."""
    raw = evidence_entry.get("audit_chain_proofs", [])
    proofs = raw if isinstance(raw, list) else []
    results: list[ProofVerification] = []
    for data in proofs:
        proof = _proof_from_dict(data)
        valid = verify_proof(proof)
        if expected_root is not None and proof.root != expected_root:
            valid = False
        results.append(ProofVerification(correlation_id=data["correlation_id"], valid=valid))
    return EvidenceVerificationResult(
        all_valid=all(r.valid for r in results),
        proofs_checked=len(results),
        results=tuple(results),
    )


def verify_bundle(entries: Sequence[dict[str, Any]], *, expected_root: str | None = None) -> bool:
    """True iff every entry's attached proofs verify (an audit-ready bundle-level check)."""
    return all(verify_evidence_proofs(e, expected_root=expected_root).all_valid for e in entries)
