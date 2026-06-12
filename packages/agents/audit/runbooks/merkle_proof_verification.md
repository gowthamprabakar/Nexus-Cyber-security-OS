# Runbook — Merkle Proof Verification (audit v0.2)

## Generate a membership proof

`audit.merkle.tree.build_merkle_tree([e.entry_hash for e in events])` then
`audit.merkle.proof.generate_proof(tree, leaf_index)`.

## Verify

`audit.merkle.proof.verify_proof(proof)` recomputes the root in O(log n) and compares to the
committed root. A tampered leaf / sibling / root fails.

## Compliance evidence

`audit.compliance_integration.evidence_chain.build_evidence_proofs(events, correlation_ids)`
attaches proofs to a compliance evidence entry; downstream verify via
`audit.compliance_integration.verify_api.verify_evidence_proofs(entry, expected_root=...)`.
