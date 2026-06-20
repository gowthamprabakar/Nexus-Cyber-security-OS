"""Fleet Test Level 1 — remediation (A.1) wiring smoke.

Tier B (action / state-mutating, SAFETY-CRITICAL). Remediation reads a detect-agent
findings.json (D.6 k8s-posture manifest findings), plans a patch, and emits OCSF 2007
Remediation-Activity records. It has NO kg_writer and run() takes NO semantic_store. This
smoke test drives the SAFEST mode — RECOMMEND — which builds the 2007 artifact but performs no
cluster mutation (no kubectl), so it needs no live cluster.

L1 is SMOKE, not capability — proves plumbing only (run completes, OCSF 2007 action shape
valid, audit chain clean, tenant isolated). Patch correctness / rollback safety is L2.

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes (RemediationReport), OCSF 2007 valid via the shared envelope-strict
    helper (A.1 findings ARE wrapped with a nexus_envelope), audit-chain integrity (tamper +
    linkage), two-tenant isolation on the emitted findings' correlation ids + tenant tags.
  * OMITS the shared fleet_testkit.assert_audit_chain helper: that helper assumes ONE linear
    hash chain (genesis → e0 → e1 → …). A.1's workspace audit.jsonl interleaves TWO independent
    F.6 chains under the same `agent="remediation"` label — the Charter context's invocation
    chain (invocation_started → tool_call → output_written → invocation_completed) AND the
    A.1 PipelineAuditor's action chain (run_started → findings_ingested → … → run_completed),
    which forks off the Charter chain's first hash. Both are valid chains, but a single linear
    walk trips on the fork. We therefore verify integrity with an A.1-specific check that
    recomputes every entry's hash (the real charter.audit tamper check) AND asserts every
    previous_hash is genesis or some prior entry's entry_hash (valid DAG linkage). Documented
    deviation, not a skipped check.
  * OMITS all kg assertions (assert_entity_written / assert_no_entities / two_tenant_disjoint
    over NodeCategory): A.1 has no kg_writer and run() accepts no semantic_store — there is no
    graph write path to assert. Documented; asserting one would be a fake-green.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.audit import GENESIS_HASH, AuditEntry, _hash_entry
from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.schemas import FindingsReport, Severity
from fleet_testkit import assert_ocsf_valid
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.agent import run
from remediation.authz import Authorization
from remediation.schemas import RemediationActionType, RemediationMode
from shared.fabric.envelope import NexusEnvelope

_NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
_OCSF_CLASS = 2007  # Remediation Activity (remediation.schemas)


def _contract(tmp_path: Path, *, customer_id: str, delegation_id: str) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id,
        source_agent="supervisor",
        target_agent="remediation",
        customer_id=customer_id,
        task="fleet-test L1 wiring smoke for remediation",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=20,
            mb_written=10,
        ),
        permitted_tools=["read_findings", "apply_patch"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _seed_findings_json(tmp_path: Path, *, customer_id: str) -> Path:
    """Write a real D.6 findings.json by round-tripping through k8s-posture's normalizer.

    Operators reading this see the SAME bytes the real detect agent would emit (swiss-bar #3).
    """
    manifest = ManifestFinding(
        rule_id="run-as-root",  # planner maps this to K8S_PATCH_RUN_AS_NON_ROOT
        rule_title="Run As Root",
        severity=Severity.HIGH,
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=_NOW,
    )
    envelope = NexusEnvelope(
        correlation_id="corr_seed",
        tenant_id=customer_id,
        agent_id="k8s_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    cp_findings = normalize_manifest([manifest], envelope=envelope, scan_time=_NOW)
    report = FindingsReport(
        agent="k8s_posture",
        agent_version="0.1.0",
        customer_id=customer_id,
        run_id="run_seed",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
    )
    for f in cp_findings:
        report.add_finding(f)
    path = tmp_path / "findings.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def _assert_interleaved_audit_chains(audit_path: Path) -> int:
    """Verify A.1's interleaved-chains audit.jsonl (see module docstring for why the shared
    single-linear-chain helper can't be used here).

    For every entry: (1) recompute its entry_hash with the real charter.audit algorithm
    (tamper check); (2) assert its previous_hash is GENESIS or equals some PRIOR entry's
    entry_hash (valid linkage in the interleaved Charter + PipelineAuditor chains).
    """
    assert audit_path.is_file(), f"audit log missing at {audit_path}"
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert lines, f"audit log at {audit_path} is empty (no chained entries)"

    seen_hashes: set[str] = {GENESIS_HASH}
    for i, line in enumerate(lines):
        entry = AuditEntry.from_json(line)
        recomputed = _hash_entry(
            entry.timestamp,
            entry.agent,
            entry.run_id,
            entry.action,
            entry.payload,
            entry.previous_hash,
        )
        assert recomputed == entry.entry_hash, (
            f"audit entry {i} hash mismatch (tampered/corrupt): {recomputed} != {entry.entry_hash}"
        )
        assert entry.previous_hash in seen_hashes, (
            f"audit entry {i} previous_hash {entry.previous_hash} links to no prior entry "
            f"(broken linkage)"
        )
        seen_hashes.add(entry.entry_hash)
    return len(lines)


def _emitted(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


def _correlation_ids(findings: list[dict[str, Any]]) -> set[str]:
    return {f["nexus_envelope"]["correlation_id"] for f in findings}


@pytest.mark.asyncio
async def test_wiring_remediation(tmp_path: Path) -> None:
    """Tier B action: run completes · OCSF 2007 action shape valid · audit-chain integrity
    (interleaved chains) · two-tenant isolation. (No kg assertions — A.1 has no kg_writer.)"""
    auth = Authorization(authorized_actions=[RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value])

    # tenant A
    findings_a = _seed_findings_json(tmp_path / "a", customer_id="tenant_a")
    contract_a = _contract(
        tmp_path / "a", customer_id="tenant_a", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    )
    report_a = await run(
        contract_a,
        findings_path=findings_a,
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )

    assert report_a.findings, "remediation emitted no OCSF 2007 records"
    emitted_a = _emitted(tmp_path / "a" / "ws")
    assert emitted_a, "no findings written to findings.json"
    for finding in emitted_a:
        assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)
    # A.1-specific action-shape discriminator: the finding_info.types carries the action type.
    assert emitted_a[0]["finding_info"]["types"][0].startswith("remediation_"), (
        f"expected a remediation action type, got {emitted_a[0]['finding_info']['types']!r}"
    )
    _assert_interleaved_audit_chains(tmp_path / "a" / "ws" / "audit.jsonl")

    # tenant isolation: a second tenant's run re-stamps its own tenant into each emitted
    # action; the emitted correlation-id sets + tenant tags are disjoint.
    findings_b = _seed_findings_json(tmp_path / "b", customer_id="tenant_b")
    contract_b = _contract(
        tmp_path / "b", customer_id="tenant_b", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0"
    )
    await run(
        contract_b,
        findings_path=findings_b,
        mode=RemediationMode.RECOMMEND,
        authorization=auth,
    )
    emitted_b = _emitted(tmp_path / "b" / "ws")

    ids_a = _correlation_ids(emitted_a)
    ids_b = _correlation_ids(emitted_b)
    assert ids_a and ids_b, "one tenant emitted no correlation ids — disjointness check vacuous"
    assert not (ids_a & ids_b), (
        f"cross-tenant correlation-id leak between tenant_a and tenant_b: {ids_a & ids_b}"
    )
    for finding in emitted_a:
        assert finding["nexus_envelope"]["tenant_id"] == "tenant_a"
    for finding in emitted_b:
        assert finding["nexus_envelope"]["tenant_id"] == "tenant_b"
