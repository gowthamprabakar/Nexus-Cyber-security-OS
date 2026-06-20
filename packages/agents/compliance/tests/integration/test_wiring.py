"""Fleet Test Level 1 — compliance (D.9/D.6) wiring smoke.

Tier B (read-only consumer). Compliance does NOT scan cloud directly — it CONSUMES
sibling agents' OCSF 2003 findings.json (F.3 cloud-posture + D.5 data-security), correlates
them to CIS controls, and re-emits aggregated OCSF 2003 ComplianceFindings. To exercise the
real wiring we must SEED a sibling workspace so the run has something to aggregate.

L1 is SMOKE, not capability — it proves the plumbing (run completes, OCSF valid, audit chain
clean, tenant isolated). It does NOT measure correctness of the control mapping (that is L2).

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes, OCSF 2003 valid (enveloped), audit chain hash-verifies,
    two-tenant isolation on the EMITTED findings (compliance re-stamps a fresh per-tenant
    correlation/run id into each finding).
  * OMITS assert_entity_written: this harness drives compliance WITHOUT a semantic_store
    (offline consumer path), so no kg_writer runs. Compliance DOES ship an optional kg_writer
    (framework/control entities) gated behind a passed semantic_store; that write path is a
    capability-level concern (L2), not L1 wiring. Driving offline keeps the smoke test
    deterministic and focused on the OCSF-consume→re-emit spine, which is compliance's
    load-bearing wiring. Documented deviation, not a fake-green.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.schemas import AffectedResource, Severity
from cloud_posture.schemas import build_finding as build_cspm_finding
from compliance.agent import run
from fleet_testkit import assert_audit_chain, assert_ocsf_valid
from shared.fabric.envelope import NexusEnvelope

_NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
_OCSF_CLASS = 2003  # Compliance Finding (re-exported from cloud_posture.schemas)


def _contract(tmp_path: Path, *, customer_id: str, delegation_id: str) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id,
        source_agent="supervisor",
        target_agent="compliance",
        customer_id=customer_id,
        task="fleet-test L1 wiring smoke for compliance",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_cis_aws_benchmark"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _seed_f3_workspace(workspace: Path, *, customer_id: str) -> Path:
    """Seed a sibling F.3 cloud-posture workspace with one OCSF 2003 finding to consume.

    Reuses cloud_posture.schemas.build_finding (the real F.3 emitter) so the seed is the same
    enveloped wire shape compliance reads in production (swiss-bar #3, not mock theater).
    """
    workspace.mkdir(parents=True, exist_ok=True)
    payload = build_cspm_finding(
        finding_id="CSPM-AWS-IAM-001-alice",
        rule_id="CSPM-AWS-IAM-001",  # maps to a CIS control in the bundled mapping
        severity=Severity.HIGH,
        title="F.3 fixture",
        description="IAM user without MFA",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_iam_user",
                resource_id="alice",
                arn="arn:aws:iam::123456789012:user/alice",
            )
        ],
        detected_at=_NOW,
        envelope=NexusEnvelope(
            correlation_id="00000000-0000-0000-0000-00000000f3f3",
            tenant_id=customer_id,
            agent_id="cloud_posture",
            nlah_version="0.1.0",
            model_pin="deterministic",
            charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        ),
    ).to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "cloud_posture",
                "agent_version": "0.1.0",
                "customer_id": customer_id,
                "run_id": "run_f3",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )
    return workspace


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


def _correlation_ids(findings: list[dict[str, Any]]) -> set[str]:
    return {f["nexus_envelope"]["correlation_id"] for f in findings}


@pytest.mark.asyncio
async def test_wiring_compliance(tmp_path: Path) -> None:
    """Tier B read-only: run completes · OCSF 2003 valid · audit chain hash-verifies ·
    two-tenant isolation on emitted findings. (No kg assertion — driven offline, see module
    docstring.)"""
    # tenant A
    f3_a = tmp_path / "a" / "f3"
    _seed_f3_workspace(f3_a, customer_id="tenant_a")
    contract_a = _contract(
        tmp_path / "a", customer_id="tenant_a", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    )
    report_a = await run(contract_a, cloud_posture_workspace=f3_a)

    assert report_a.total >= 1, "compliance emitted no findings from the seeded sibling"
    findings_a = _findings(tmp_path / "a" / "ws")
    assert findings_a, "no findings written to findings.json"
    for finding in findings_a:
        assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

    assert_audit_chain(tmp_path / "a" / "ws" / "audit.jsonl")

    # tenant isolation: same seeded input under tenant_b → compliance re-stamps each emitted
    # finding with the tenant_b correlation/run id, so the two tenants' emitted correlation-id
    # sets are disjoint (no cross-tenant leak through the consume→re-emit spine).
    f3_b = tmp_path / "b" / "f3"
    _seed_f3_workspace(f3_b, customer_id="tenant_b")
    contract_b = _contract(
        tmp_path / "b", customer_id="tenant_b", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0"
    )
    report_b = await run(contract_b, cloud_posture_workspace=f3_b)
    assert report_b.total >= 1
    findings_b = _findings(tmp_path / "b" / "ws")

    ids_a = _correlation_ids(findings_a)
    ids_b = _correlation_ids(findings_b)
    assert ids_a and ids_b, "one tenant emitted no correlation ids — disjointness check vacuous"
    assert not (ids_a & ids_b), (
        f"cross-tenant correlation-id leak between tenant_a and tenant_b: {ids_a & ids_b}"
    )
    # Each emitted finding's envelope carries its own tenant — never the other tenant's.
    for finding in findings_a:
        assert finding["nexus_envelope"]["tenant_id"] == "tenant_a"
    for finding in findings_b:
        assert finding["nexus_envelope"]["tenant_id"] == "tenant_b"


@pytest.mark.asyncio
async def test_wiring_compliance_empty_offline(tmp_path: Path) -> None:
    """No sibling workspace → 0 findings, but findings.json + audit chain still emit (the
    inert/empty consumer path stays well-formed)."""
    contract = _contract(tmp_path, customer_id="t_off", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ")
    report = await run(contract)
    assert report.total == 0
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "compliance"
    assert payload["findings"] == []
    assert_audit_chain(tmp_path / "ws" / "audit.jsonl")
