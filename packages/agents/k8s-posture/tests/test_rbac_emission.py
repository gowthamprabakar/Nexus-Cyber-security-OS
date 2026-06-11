"""D.6 v0.2 Task 13 — RBAC + runtime finding emission to OCSF 2003 tests."""

from __future__ import annotations

from datetime import UTC, datetime

from k8s_posture.rbac.emission import emit_rbac_findings, emit_runtime_findings
from k8s_posture.rbac.over_privileged import RbacFinding
from k8s_posture.runtime.posture_rules import RuntimeViolation
from k8s_posture.schemas import FINDING_ID_RE
from shared.fabric.envelope import NexusEnvelope

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="k8s_posture@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def test_rbac_emission_class_uid_2003() -> None:
    f = RbacFinding(
        "cluster-admin-binding", "critical", "ClusterRoleBinding", "ab", "", "cluster-admin to SA"
    )
    [finding] = emit_rbac_findings([f], envelope=_envelope(), scan_time=_T)
    d = finding.to_dict()
    assert d["class_uid"] == 2003
    assert finding.severity == "critical"


def test_rbac_finding_id_matches_regex() -> None:
    f = RbacFinding("wildcard-permissions", "high", "ClusterRole", "admin-like", "", "msg")
    [finding] = emit_rbac_findings([f], envelope=_envelope(), scan_time=_T)
    assert FINDING_ID_RE.match(finding.finding_id)
    assert "-RBAC-" in finding.finding_id


def test_runtime_emission_class_uid_2003() -> None:
    v = RuntimeViolation("privileged-container", "critical", "prod", "web", "app", "privileged")
    [finding] = emit_runtime_findings([v], envelope=_envelope(), scan_time=_T)
    assert finding.to_dict()["class_uid"] == 2003
    assert FINDING_ID_RE.match(finding.finding_id) and "-RUNTIME-" in finding.finding_id


def test_runtime_finding_without_container() -> None:
    v = RuntimeViolation("host-network", "high", "prod", "web", "", "hostNetwork")
    [finding] = emit_runtime_findings([v], envelope=_envelope(), scan_time=_T)
    assert FINDING_ID_RE.match(finding.finding_id)


def test_empty_inputs() -> None:
    assert emit_rbac_findings([], envelope=_envelope(), scan_time=_T) == ()
    assert emit_runtime_findings([], envelope=_envelope(), scan_time=_T) == ()


def test_sequence_numbers_distinct() -> None:
    fs = [
        RbacFinding("wildcard-permissions", "high", "ClusterRole", "r1", "", "m"),
        RbacFinding("wildcard-permissions", "high", "ClusterRole", "r2", "", "m"),
    ]
    ids = [f.finding_id for f in emit_rbac_findings(fs, envelope=_envelope(), scan_time=_T)]
    assert ids[0] != ids[1] and len(set(ids)) == 2
