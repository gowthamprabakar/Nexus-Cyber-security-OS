"""WI-C2 + WI-C7 — live multi-emitter consumption end-to-end (compliance v0.2 Task 19).

Two-layer per the WI-V6 / WI-I4 / WI-T4 / WI-R4 / WI-N4 / WI-K4 lineage:

1. **Offline layer (every push):** the real consumption pipeline — F.3 + D.5 + k8s-posture
   OCSF 2003 reports → consumption → roll-up → **PASS + FAIL emission** → evidence bundle +
   signed manifest — exercised across **all 4 CIS frameworks** with synthetic reports.
2. **Gated-live layer (`NEXUS_LIVE_COMPLIANCE=1`):** probes for live emitter reports; skipped
   in CI.

Honest scope (WI-C4): this is e2e **through emission**; wiring it into the agent's
continuous `run()` loop is the **Phase C** consolidated retrofit — the offline `run()` stays
the deterministic OCSF-emitting path (WI-C5 byte-identical).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from cloud_posture.schemas import AffectedResource, Severity
from compliance.attestation import build_attestation, control_can_be_attested
from compliance.consumption import evaluate_framework, source_evaluation
from compliance.evidence.bundle import build_evidence_bundle, build_evidence_entry
from compliance.evidence.chain import build_manifest, verify_manifest
from compliance.evidence.export import export_json, export_report_text
from compliance.live_lane import emitters_reachable
from compliance.schemas import (
    ComplianceFramework,
    build_finding,
    build_pass_finding,
)
from compliance.tools.cis_aws_benchmark import read_cis_aws_benchmark
from compliance.tools.cis_azure_benchmark import read_cis_azure_benchmark
from compliance.tools.cis_gcp_benchmark import read_cis_gcp_benchmark
from compliance.tools.cis_k8s_benchmark import read_cis_k8s_benchmark
from shared.fabric.envelope import NexusEnvelope

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)
_TS = _T.isoformat()

_FRAMEWORKS = {
    ComplianceFramework.CIS_AWS_V3: (read_cis_aws_benchmark, "cloud_posture"),
    ComplianceFramework.CIS_AZURE_V2: (read_cis_azure_benchmark, "multi_cloud_posture"),
    ComplianceFramework.CIS_GCP_V2: (read_cis_gcp_benchmark, "multi_cloud_posture"),
    ComplianceFramework.CIS_K8S_V18: (read_cis_k8s_benchmark, "k8s_posture"),
}


def _report(agent: str, *rule_ids: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "findings": [
            {"class_uid": 2003, "compliance": {"control": rid, "status": "Failed"}}
            for rid in rule_ids
        ],
    }


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_c",
        tenant_id="cust_test",
        agent_id="compliance",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="i",
    )


def _affected() -> list[Any]:
    return [
        AffectedResource(
            cloud="aws",
            account_id="1",
            region="us-east-1",
            resource_type="account",
            resource_id="1",
            arn="arn:aws:iam::1:root",
        )
    ]


# ------------------- offline layer: all 4 frameworks ----------------------


def test_all_four_frameworks_roll_up() -> None:
    # WI-C7: every CIS framework is exercised through consumption + roll-up.
    for framework, (reader, agent) in _FRAMEWORKS.items():
        controls = asyncio.run(reader())
        rollup = evaluate_framework(framework.value, _report(agent), controls, source_agent=agent)
        assert rollup.pass_count > 0, framework.value  # all wired controls pass on a clean report


def test_pass_and_fail_emission_cis_aws() -> None:
    controls = asyncio.run(read_cis_aws_benchmark())
    report = _report("cloud_posture", "CSPM-AWS-EC2-001")  # one failing rule
    evaluated, failing = source_evaluation(report, controls, source_agent="cloud_posture")

    pass_count = fail_count = 0
    for i, c in enumerate(controls, start=1):
        mapped = [m.source_rule_id for m in c.source_mappings if m.source_agent == "cloud_posture"]
        if not mapped:
            continue
        if control_can_be_attested(mapped, evaluated_rule_ids=evaluated, failing_rule_ids=failing):
            att = build_attestation(
                control_id=c.control_id,
                framework="cis_aws_v3",
                mapped_rule_ids=mapped,
                attested_at=_TS,
            ).to_evidence()
            f = build_pass_finding(
                finding_id=f"COMPLIANCE-CIS_AWS_V3-{c.control_id}-{i:03d}-pass",
                framework=ComplianceFramework.CIS_AWS_V3,
                control_id=c.control_id,
                title="pass",
                description="d",
                affected=_affected(),
                detected_at=_T,
                envelope=_envelope(),
                attestation=att,
            )
            assert f.to_dict()["compliance"]["status"] == "Passed"
            pass_count += 1
        elif not set(mapped).isdisjoint(failing):
            f = build_finding(
                finding_id=f"COMPLIANCE-CIS_AWS_V3-{c.control_id}-{i:03d}-fail",
                framework=ComplianceFramework.CIS_AWS_V3,
                control_id=c.control_id,
                severity=Severity.HIGH,
                title="fail",
                description="d",
                affected=_affected(),
                detected_at=_T,
                envelope=_envelope(),
            )
            assert f.to_dict()["compliance"]["status"] == "Failed"
            fail_count += 1
    assert pass_count > 0 and fail_count >= 1  # both PASS + FAIL emitted


def test_evidence_bundle_and_manifest_end_to_end() -> None:
    controls = asyncio.run(read_cis_k8s_benchmark())
    report = _report("k8s_posture", "privileged-container")
    evaluated, failing = source_evaluation(report, controls, source_agent="k8s_posture")

    entries = []
    for c in controls:
        mapped = [m.source_rule_id for m in c.source_mappings if m.source_agent == "k8s_posture"]
        status = (
            "fail"
            if not set(mapped).isdisjoint(failing)
            else (
                "pass"
                if control_can_be_attested(
                    mapped, evaluated_rule_ids=evaluated, failing_rule_ids=failing
                )
                else "not_evaluated"
            )
        )
        entries.append(
            build_evidence_entry(
                framework_id="cis_k8s_v18",
                control_id=c.control_id,
                status=status,
                source_finding_ids=[],
                timestamp=_TS,
            )
        )
    bundle = build_evidence_bundle(framework_id="cis_k8s_v18", generated_at=_TS, entries=entries)
    manifest = build_manifest(
        framework_id="cis_k8s_v18", entry_hashes=[e.entry_hash for e in entries]
    )
    assert verify_manifest(manifest, [e.entry_hash for e in entries]) is True
    assert json.loads(export_json(bundle, manifest))["bundle"]["entry_count"] == len(entries)
    assert "Compliance Evidence — cis_k8s_v18" in export_report_text(bundle, manifest)
    # 5.2.2 failed via the runtime mapping.
    assert any(e.status == "fail" for e in entries)


# --------------------------- gated-live layer ----------------------------


def test_live_emitters_reachable(compliance_gate: None) -> None:
    ok, reason = emitters_reachable(["cloud_posture"])
    assert ok, f"emitters unreachable: {reason}"
