"""audit v0.2 Task 12 — evidence chain verification API tests (Q4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.compliance_integration.evidence_chain import (
    attach_proofs_to_evidence,
    build_evidence_proofs,
)
from audit.compliance_integration.verify_api import (
    verify_bundle,
    verify_evidence_proofs,
)
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
        entry_hash = _hash_entry(
            timestamp=ts,
            agent="compliance",
            run_id=f"corr-{i:03d}",
            action="evaluate",
            payload={"i": i},
            previous_hash=previous_hash,
        )
        events.append(
            AuditEvent(
                tenant_id=_TENANT,
                correlation_id=f"corr-{i:03d}",
                agent_id="compliance",
                action="evaluate",
                payload={"i": i},
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                emitted_at=emitted_at,
                source="jsonl:/tmp/c.jsonl",
            )
        )
        previous_hash = entry_hash
    return events


def _evidence(corr_ids: list[str], n: int = 5) -> dict:
    proofs = build_evidence_proofs(_chain(n), corr_ids)
    return attach_proofs_to_evidence({"control_id": "CIS-1.1"}, proofs)


def test_valid_proofs_verify() -> None:
    result = verify_evidence_proofs(_evidence(["corr-000", "corr-003"]))
    assert result.all_valid is True and result.proofs_checked == 2


def test_no_proofs_vacuously_valid() -> None:
    result = verify_evidence_proofs({"control_id": "CIS-1.1"})
    assert result.all_valid is True and result.proofs_checked == 0


def test_tampered_leaf_fails() -> None:
    evidence = _evidence(["corr-001"])
    evidence["audit_chain_proofs"][0]["leaf_hash"] = "0" * 64
    result = verify_evidence_proofs(evidence)
    assert result.all_valid is False


def test_expected_root_match() -> None:
    chain = _chain(4)
    proofs = build_evidence_proofs(chain, ["corr-001"])
    evidence = attach_proofs_to_evidence({"control_id": "X"}, proofs)
    result = verify_evidence_proofs(evidence, expected_root=proofs[0].chain_root)
    assert result.all_valid is True


def test_expected_root_mismatch_fails() -> None:
    evidence = _evidence(["corr-001"])
    result = verify_evidence_proofs(evidence, expected_root="0" * 64)
    assert result.all_valid is False


def test_per_proof_results() -> None:
    result = verify_evidence_proofs(_evidence(["corr-000", "corr-002"]))
    assert {r.correlation_id for r in result.results} == {"corr-000", "corr-002"}


def test_verify_bundle() -> None:
    bundle = [_evidence(["corr-000"]), _evidence(["corr-001"])]
    assert verify_bundle(bundle) is True


def test_verify_bundle_detects_tamper() -> None:
    good = _evidence(["corr-000"])
    bad = _evidence(["corr-001"])
    bad["audit_chain_proofs"][0]["leaf_hash"] = "0" * 64
    assert verify_bundle([good, bad]) is False
