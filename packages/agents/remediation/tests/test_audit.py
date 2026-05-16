"""Tests for `remediation.audit` — F.6 AuditLog wiring."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from remediation.action_classes._common import wrap_container_patch
from remediation.audit import (
    ACTION_ACTION_REFUSED,
    ACTION_ARTIFACT_GENERATED,
    ACTION_BLAST_RADIUS_REFUSED,
    ACTION_DRY_RUN_COMPLETED,
    ACTION_EXECUTE_COMPLETED,
    ACTION_EXECUTE_FAILED,
    ACTION_FINDINGS_INGESTED,
    ACTION_ROLLBACK_COMPLETED,
    ACTION_RUN_COMPLETED,
    ACTION_RUN_STARTED,
    PipelineAuditor,
    all_action_names,
)
from remediation.schemas import (
    RemediationActionType,
    RemediationArtifact,
    RemediationMode,
    RemediationOutcome,
)
from remediation.tools.kubectl_executor import PatchResult
from remediation.validator import ValidationResult


def _artifact() -> RemediationArtifact:
    from k8s_posture.tools.manifests import ManifestFinding

    NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
    finding = ManifestFinding(
        rule_id="run-as-root",
        rule_title="Run As Root",
        severity="high",
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///x",
        detected_at=NOW,
    )
    leaf = {"securityContext": {"runAsNonRoot": True}}
    inverse_leaf = {"securityContext": {"runAsNonRoot": None}}
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        api_version="apps/v1",
        kind="Deployment",
        namespace="production",
        name="frontend",
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid="CSPM-KUBERNETES-MANIFEST-001-x",
        correlation_id="corr-test",
    )


def _patch_result_ok(*, dry_run: bool = False) -> PatchResult:
    return PatchResult(
        exit_code=0,
        stdout="deployment.apps/frontend patched",
        stderr="",
        dry_run=dry_run,
        pre_patch_hash="a" * 64,
        post_patch_hash="b" * 64,
        pre_patch_resource={"kind": "Deployment"},
        post_patch_resource={"kind": "Deployment", "patched": True},
    )


def _patch_result_fail() -> PatchResult:
    return PatchResult(
        exit_code=1,
        stdout="",
        stderr="error: admission webhook denied",
        dry_run=False,
        pre_patch_hash=None,
        post_patch_hash=None,
        pre_patch_resource=None,
        post_patch_resource=None,
    )


def _read_chain(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------- vocabulary ----------------------------------


def test_action_vocabulary_count() -> None:
    """v0.1 emits exactly 11 distinct action names — keep the table in audit.py in sync."""
    assert len(all_action_names()) == 11


def test_action_names_are_unique() -> None:
    """No duplicate strings — every action means one thing."""
    names = all_action_names()
    assert len(names) == len(set(names))


def test_all_action_names_carry_remediation_prefix() -> None:
    """Every A.1 action string is namespaced under `remediation.*` so the F.6 query
    surface can filter A.1's contribution from D.6's audit trail."""
    for name in all_action_names():
        assert name.startswith("remediation.")


# ---------------------------- PipelineAuditor construction ----------------


def test_pipeline_auditor_creates_audit_jsonl(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    assert auditor.path.exists() is False  # not until first append
    # tail_hash starts at genesis.
    assert len(auditor.tail_hash) == 64  # 32-byte SHA-256 hex


# ---------------------------- run boundary --------------------------------


def test_run_started_emits_entry(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    entry = auditor.run_started(
        mode=RemediationMode.EXECUTE,
        findings_path=str(tmp_path / "findings.json"),
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    assert entry.action == ACTION_RUN_STARTED
    chain = _read_chain(auditor.path)
    assert len(chain) == 1
    assert chain[0]["payload"]["mode"] == "execute"
    assert chain[0]["payload"]["max_actions_per_run"] == 5


def test_run_completed_records_outcome_counts(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.run_completed(
        outcome_counts={"executed_validated": 3, "executed_rolled_back": 1},
        total_actions=4,
    )
    chain = _read_chain(auditor.path)
    assert chain[-1]["action"] == ACTION_RUN_COMPLETED
    assert chain[-1]["payload"]["total_actions"] == 4
    assert chain[-1]["payload"]["outcome_counts"]["executed_validated"] == 3


# ---------------------------- Stage 1 --------------------------------------


def test_findings_ingested_records_count(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.findings_ingested(count=7, source_path=str(tmp_path / "findings.json"))
    chain = _read_chain(auditor.path)
    assert chain[0]["action"] == ACTION_FINDINGS_INGESTED
    assert chain[0]["payload"]["count"] == 7


# ---------------------------- Stage 2 --------------------------------------


def test_action_refused_carries_rule_id_and_reason(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.action_refused(
        rule_id="privileged-container",
        reason="no v0.1 action class for rule_id='privileged-container'",
    )
    chain = _read_chain(auditor.path)
    assert chain[0]["action"] == ACTION_ACTION_REFUSED
    assert chain[0]["payload"]["rule_id"] == "privileged-container"
    assert chain[0]["payload"]["outcome"] == RemediationOutcome.REFUSED_UNAUTHORIZED.value


def test_blast_radius_refused_records_cap_and_request(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.blast_radius_refused(requested=8, cap=5)
    chain = _read_chain(auditor.path)
    assert chain[0]["action"] == ACTION_BLAST_RADIUS_REFUSED
    assert chain[0]["payload"]["requested_actions"] == 8
    assert chain[0]["payload"]["max_actions_per_run"] == 5


# ---------------------------- Stage 3 --------------------------------------


def test_artifact_generated_records_artifact_handle(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.artifact_generated(_artifact())
    chain = _read_chain(auditor.path)
    payload = chain[0]["payload"]
    assert chain[0]["action"] == ACTION_ARTIFACT_GENERATED
    assert payload["action_type"] == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    assert payload["kind"] == "Deployment"
    assert payload["namespace"] == "production"
    assert payload["name"] == "frontend"
    assert payload["correlation_id"] == "corr-test"
    # Patch body itself is NOT in the audit — it's on the RemediationFinding;
    # cross-reference by correlation_id.
    assert "patch_body" not in payload


# ---------------------------- Stage 4 --------------------------------------


def test_dry_run_completed_success(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.dry_run_completed(_artifact(), _patch_result_ok(dry_run=True))
    chain = _read_chain(auditor.path)
    payload = chain[0]["payload"]
    assert chain[0]["action"] == ACTION_DRY_RUN_COMPLETED
    assert payload["outcome"] == RemediationOutcome.DRY_RUN_ONLY.value
    assert payload["dry_run"] is True
    assert payload["succeeded"] is True


def test_dry_run_completed_failure(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.dry_run_completed(_artifact(), _patch_result_fail())
    payload = _read_chain(auditor.path)[0]["payload"]
    assert payload["outcome"] == RemediationOutcome.DRY_RUN_FAILED.value
    assert payload["succeeded"] is False
    assert "admission webhook denied" in payload["stderr_head"]


# ---------------------------- Stage 5 --------------------------------------


def test_execute_completed_includes_pre_post_hashes(tmp_path: Path) -> None:
    """The pre/post-patch hashes flow through to the audit entry — operators can
    verify post-execution state matches the recorded hash to detect tampering."""
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.execute_completed(_artifact(), _patch_result_ok())
    chain = _read_chain(auditor.path)
    assert chain[0]["action"] == ACTION_EXECUTE_COMPLETED
    payload = chain[0]["payload"]
    assert payload["pre_patch_hash"] == "a" * 64
    assert payload["post_patch_hash"] == "b" * 64
    # Outcome is `pending_validation` — Stage 6 sets the final disposition.
    assert payload["outcome"] == "pending_validation"


def test_execute_failed_records_failure(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.execute_failed(_artifact(), _patch_result_fail())
    payload = _read_chain(auditor.path)[0]["payload"]
    assert _read_chain(auditor.path)[0]["action"] == ACTION_EXECUTE_FAILED
    assert payload["outcome"] == RemediationOutcome.EXECUTE_FAILED.value
    assert payload["pre_patch_hash"] is None
    assert payload["post_patch_hash"] is None


# ---------------------------- Stage 6 --------------------------------------


def test_validate_completed_records_validated_outcome(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.validate_completed(
        _artifact(),
        ValidationResult(requires_rollback=False, matched_findings=()),
    )
    payload = _read_chain(auditor.path)[0]["payload"]
    assert payload["outcome"] == RemediationOutcome.EXECUTED_VALIDATED.value
    assert payload["requires_rollback"] is False
    assert payload["matched_findings_count"] == 0


def test_validate_completed_records_rollback_outcome(tmp_path: Path) -> None:
    from k8s_posture.tools.manifests import ManifestFinding

    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    bad = ManifestFinding(
        rule_id="run-as-root",
        rule_title="x",
        severity="high",
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///x",
        detected_at=datetime.now(UTC),
    )
    auditor.validate_completed(
        _artifact(),
        ValidationResult(requires_rollback=True, matched_findings=(bad,)),
    )
    payload = _read_chain(auditor.path)[0]["payload"]
    assert payload["outcome"] == RemediationOutcome.EXECUTED_ROLLED_BACK.value
    assert payload["requires_rollback"] is True
    assert payload["matched_findings_count"] == 1


# ---------------------------- Stage 7 --------------------------------------


def test_rollback_completed_records_inverse_apply(tmp_path: Path) -> None:
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.rollback_completed(_artifact(), _patch_result_ok())
    payload = _read_chain(auditor.path)[0]["payload"]
    assert _read_chain(auditor.path)[0]["action"] == ACTION_ROLLBACK_COMPLETED
    assert payload["outcome"] == RemediationOutcome.EXECUTED_ROLLED_BACK.value
    # Post-rollback hash recorded — operators can audit the state after the inverse patch.
    assert payload["post_patch_hash"] == "b" * 64


# ---------------------------- chain integrity -----------------------------


def test_audit_chain_links_entries_via_previous_hash(tmp_path: Path) -> None:
    """F.6's hash chain primitive: entry N's `previous_hash` equals entry N-1's `entry_hash`."""
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.run_started(
        mode=RemediationMode.RECOMMEND,
        findings_path="/x",
        authorized_actions=[],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    auditor.findings_ingested(count=2, source_path="/x")
    auditor.artifact_generated(_artifact())
    auditor.run_completed(outcome_counts={}, total_actions=2)

    chain = _read_chain(auditor.path)
    assert len(chain) == 4
    # Each entry links to the previous via previous_hash == previous entry_hash.
    for i in range(1, len(chain)):
        assert chain[i]["previous_hash"] == chain[i - 1]["entry_hash"]


def test_audit_chain_tail_hash_matches_last_entry(tmp_path: Path) -> None:
    """`auditor.tail_hash` exposes the last entry's `entry_hash` for the run_completed payload."""
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    auditor.findings_ingested(count=0, source_path="/x")
    chain = _read_chain(auditor.path)
    assert auditor.tail_hash == chain[-1]["entry_hash"]


# ---------------------------- end-to-end full-pipeline audit --------------


def test_full_pipeline_audit_chain_records_all_11_actions(tmp_path: Path) -> None:
    """A run that traverses every stage emits one entry per action type."""
    auditor = PipelineAuditor(tmp_path / "audit.jsonl", run_id="run_001")
    artifact = _artifact()
    from k8s_posture.tools.manifests import ManifestFinding

    bad = ManifestFinding(
        rule_id="run-as-root",
        rule_title="x",
        severity="high",
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///x",
        detected_at=datetime.now(UTC),
    )

    auditor.run_started(
        mode=RemediationMode.EXECUTE,
        findings_path="/x",
        authorized_actions=["remediation_k8s_patch_runAsNonRoot"],
        max_actions_per_run=5,
        rollback_window_sec=300,
    )
    auditor.findings_ingested(count=3, source_path="/x")
    auditor.action_refused(rule_id="privileged-container", reason="no v0.1")
    auditor.blast_radius_refused(requested=8, cap=5)
    auditor.artifact_generated(artifact)
    auditor.dry_run_completed(artifact, _patch_result_ok(dry_run=True))
    auditor.execute_completed(artifact, _patch_result_ok())
    auditor.execute_failed(artifact, _patch_result_fail())
    auditor.validate_completed(
        artifact, ValidationResult(requires_rollback=True, matched_findings=(bad,))
    )
    auditor.rollback_completed(artifact, _patch_result_ok())
    auditor.run_completed(outcome_counts={"executed_rolled_back": 1}, total_actions=1)

    chain = _read_chain(auditor.path)
    actions_emitted = [entry["action"] for entry in chain]
    assert set(actions_emitted) == set(all_action_names())


# ---------------------------- silence unused-import warning ---------------

_ = pytest  # ensure pytest import survives the linter when no fixtures used
