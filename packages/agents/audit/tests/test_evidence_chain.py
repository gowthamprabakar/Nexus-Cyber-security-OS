"""audit v0.2 Task 11 — F.6 chain proof for compliance evidence tests (Q4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.compliance_integration.evidence_chain import (
    attach_proofs_to_evidence,
    build_evidence_proofs,
)
from audit.merkle.proof import verify_proof
from audit.schemas import AuditEvent
from charter.audit import GENESIS_HASH, _hash_entry

_TENANT = "01HV0T0000000000000000TENA"


def _chain(n: int) -> list[AuditEvent]:
    events: list[AuditEvent] = []
    previous_hash = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i in range(n):
        emitted_at = base + timedelta(seconds=i)
        ts = emitted_at.isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=ts,
            agent="compliance",
            run_id=f"corr-{i:03d}",
            action="evaluate",
            payload=payload,
            previous_hash=previous_hash,
        )
        events.append(
            AuditEvent(
                tenant_id=_TENANT,
                correlation_id=f"corr-{i:03d}",
                agent_id="compliance",
                action="evaluate",
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                emitted_at=emitted_at,
                source="jsonl:/tmp/c.jsonl",
            )
        )
        previous_hash = entry_hash
    return events


def test_build_proof_for_cited_entry() -> None:
    proofs = build_evidence_proofs(_chain(4), ["corr-002"])
    assert len(proofs) == 1 and proofs[0].correlation_id == "corr-002"
    assert proofs[0].leaf_index == 2


def test_generated_proof_verifies() -> None:
    proofs = build_evidence_proofs(_chain(5), ["corr-000", "corr-003"])
    for p in proofs:
        assert verify_proof(p.proof) is True


def test_unknown_correlation_skipped() -> None:
    proofs = build_evidence_proofs(_chain(3), ["corr-009"])
    assert proofs == ()


def test_chain_root_consistent() -> None:
    proofs = build_evidence_proofs(_chain(4), ["corr-000", "corr-001"])
    roots = {p.chain_root for p in proofs}
    assert len(roots) == 1  # all proofs commit to the same chain root


def test_to_dict_serializable() -> None:
    [proof] = build_evidence_proofs(_chain(4), ["corr-001"])
    d = proof.to_dict()
    assert d["correlation_id"] == "corr-001" and "steps" in d and "chain_root" in d


def test_attach_proofs_returns_new_dict() -> None:
    evidence = {"control_id": "CIS-1.1", "status": "PASS", "source_finding_ids": ["corr-000"]}
    proofs = build_evidence_proofs(_chain(2), ["corr-000"])
    attached = attach_proofs_to_evidence(evidence, proofs)
    assert "audit_chain_proofs" in attached and len(attached["audit_chain_proofs"]) == 1
    assert "audit_chain_proofs" not in evidence  # original untouched (no cross-agent mutation)


def test_empty() -> None:
    assert build_evidence_proofs([], ["x"]) == ()
    assert build_evidence_proofs(_chain(2), []) == ()
