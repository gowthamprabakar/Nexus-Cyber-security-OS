"""Tests for `remediation.schemas` — OCSF v1.3 `class_uid 2007` Remediation Activity."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cloud_posture.schemas import AffectedResource, Severity
from remediation.schemas import (
    OCSF_CATEGORY_UID,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    REM_FINDING_ID_RE,
    RemediationActionType,
    RemediationArtifact,
    RemediationFinding,
    RemediationMode,
    RemediationOutcome,
    RemediationReport,
    build_remediation_finding,
    outcome_severity,
)
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="remediation@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _resource() -> AffectedResource:
    return AffectedResource(
        cloud="kubernetes",
        account_id="production",
        region="cluster",
        resource_type="Deployment",
        resource_id="production/frontend",
        arn="k8s://workload/production/Deployment/frontend",
    )


def _artifact(
    *,
    action_type: RemediationActionType = RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
    source_finding_uid: str = "CSPM-KUBERNETES-MANIFEST-001-run-as-root-frontend",
) -> RemediationArtifact:
    return RemediationArtifact(
        action_type=action_type,
        api_version="apps/v1",
        kind="Deployment",
        namespace="production",
        name="frontend",
        patch_strategy="strategic",
        patch_body={"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": True}}}}},
        inverse_patch_body={
            "spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": None}}}}
        },
        source_finding_uid=source_finding_uid,
        correlation_id="corr-" + source_finding_uid,
    )


# ---------------------------- enum + constants ----------------------------


def test_ocsf_class_uid_is_2007() -> None:
    """A.1 is the first producer of OCSF v1.3 class_uid 2007 Remediation Activity."""
    assert OCSF_CLASS_UID == 2007


def test_ocsf_category_is_findings() -> None:
    """OCSF puts Remediation Activity in the same category as Compliance Finding."""
    assert OCSF_CATEGORY_UID == 2


def test_ocsf_version_matches_substrate() -> None:
    assert OCSF_VERSION == "1.3.0"


def test_remediation_action_types_count() -> None:
    """v0.1 ships 5 action classes — one per D.6 rule_id that's safe to auto-patch."""
    assert len(list(RemediationActionType)) == 5


def test_remediation_mode_values() -> None:
    assert {m.value for m in RemediationMode} == {"recommend", "dry_run", "execute"}


def test_remediation_outcome_values() -> None:
    expected = {
        "recommended_only",
        "dry_run_only",
        "executed_validated",
        "executed_rolled_back",
        "refused_unauthorized",
        "refused_blast_radius",
        "refused_promotion_gate",  # added in v0.1.1 — earned-autonomy pre-flight gate
        "dry_run_failed",
        "execute_failed",
    }
    assert {o.value for o in RemediationOutcome} == expected


# ---------------------------- outcome_severity ----------------------------


def test_recommended_only_is_info_severity() -> None:
    assert outcome_severity(RemediationOutcome.RECOMMENDED_ONLY) == Severity.INFO


def test_executed_validated_is_info_severity() -> None:
    """A successful execute is INFO — not a problem."""
    assert outcome_severity(RemediationOutcome.EXECUTED_VALIDATED) == Severity.INFO


def test_executed_rolled_back_is_medium_severity() -> None:
    """Rollback means the fix didn't work; operator should know."""
    assert outcome_severity(RemediationOutcome.EXECUTED_ROLLED_BACK) == Severity.MEDIUM


def test_refused_unauthorized_is_medium_severity() -> None:
    assert outcome_severity(RemediationOutcome.REFUSED_UNAUTHORIZED) == Severity.MEDIUM


def test_dry_run_failed_is_high_severity() -> None:
    """A dry-run failure means our apply path is broken — HIGH."""
    assert outcome_severity(RemediationOutcome.DRY_RUN_FAILED) == Severity.HIGH


# ---------------------------- REM_FINDING_ID_RE ---------------------------


@pytest.mark.parametrize(
    "fid,expected",
    [
        ("REM-K8S-001-runasnonroot-frontend", True),
        ("REM-AWS-042-iam-revoke-public-bucket", True),
        ("REM-K8S-999-very-long-context-string-allowed-here", True),
        # Bad shape:
        ("REM-K8S-1-too-short", False),  # need 3 digits
        ("REM-k8s-001-lowercase-target", False),  # target must be uppercase
        ("CSPM-KUBERNETES-CIS-001-x", False),  # wrong prefix
        ("REM-K8S-001-UPPER-context", False),  # context must be lowercase
        ("REM-K8S-001-with spaces", False),  # no spaces allowed
    ],
)
def test_rem_finding_id_regex(fid: str, expected: bool) -> None:
    matched = REM_FINDING_ID_RE.match(fid) is not None
    assert matched is expected, f"unexpected REM_FINDING_ID_RE match for {fid!r}"


# ---------------------------- artifact model ------------------------------


def test_artifact_has_patch_and_inverse() -> None:
    a = _artifact()
    assert a.patch_body
    assert a.inverse_patch_body
    assert a.source_finding_uid.startswith("CSPM-")
    assert a.correlation_id.startswith("corr-")


def test_artifact_default_patch_strategy_is_strategic() -> None:
    a = RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        api_version="apps/v1",
        kind="Deployment",
        namespace="production",
        name="frontend",
        patch_body={"x": 1},
        inverse_patch_body={"x": None},
        source_finding_uid="CSPM-KUBERNETES-MANIFEST-001-x",
        correlation_id="corr-x",
    )
    assert a.patch_strategy == "strategic"


# ---------------------------- build_remediation_finding -------------------


def test_build_remediation_finding_minimal() -> None:
    f = build_remediation_finding(
        finding_id="REM-K8S-001-runasnonroot-frontend",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="Apply runAsNonRoot to production/Deployment/frontend",
        description="Patch generated; no execution in recommend mode.",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
        artifact=_artifact(),
    )
    raw = f.to_dict()
    assert raw["class_uid"] == 2007
    assert raw["category_uid"] == 2
    assert raw["activity_id"] == 1
    assert raw["type_uid"] == 2007 * 100 + 1
    assert f.finding_id == "REM-K8S-001-runasnonroot-frontend"


def test_build_finding_id_regex_violation_raises() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_remediation_finding(
            finding_id="not-a-valid-rem-id",
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            outcome=RemediationOutcome.RECOMMENDED_ONLY,
            title="x",
            description="x",
            affected=[_resource()],
            detected_at=NOW,
            envelope=_envelope(),
        )


def test_build_finding_empty_affected_raises() -> None:
    with pytest.raises(ValueError, match="affected resources"):
        build_remediation_finding(
            finding_id="REM-K8S-001-x",
            action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
            outcome=RemediationOutcome.RECOMMENDED_ONLY,
            title="x",
            description="x",
            affected=[],
            detected_at=NOW,
            envelope=_envelope(),
        )


# ---------------------------- typed wrapper -------------------------------


def test_finding_carries_action_type() -> None:
    f = build_remediation_finding(
        finding_id="REM-K8S-001-runasnonroot-frontend",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
    )
    assert f.action_type == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT


def test_finding_carries_outcome() -> None:
    f = build_remediation_finding(
        finding_id="REM-K8S-001-x",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.EXECUTED_VALIDATED,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
    )
    assert f.outcome == RemediationOutcome.EXECUTED_VALIDATED


def test_finding_envelope_round_trips() -> None:
    env = _envelope()
    f = build_remediation_finding(
        finding_id="REM-K8S-001-x",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=env,
    )
    assert f.envelope.correlation_id == "corr_xyz"
    assert f.envelope.tenant_id == "cust_test"


def test_finding_includes_artifact_evidence() -> None:
    """When an artifact is passed in, it shows up in evidences[] (Operators see the
    patch payload + inverse + lineage in findings.json)."""
    f = build_remediation_finding(
        finding_id="REM-K8S-001-x",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
        artifact=_artifact(),
    )
    raw = f.to_dict()
    evs = raw["evidences"]
    artifact_evs = [e for e in evs if e.get("kind") == "remediation-artifact"]
    assert len(artifact_evs) == 1
    assert artifact_evs[0]["action_type"] == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT.value
    assert artifact_evs[0]["target"]["namespace"] == "production"
    assert artifact_evs[0]["target"]["name"] == "frontend"


def test_finding_without_artifact_omits_artifact_evidence() -> None:
    f = build_remediation_finding(
        finding_id="REM-K8S-001-x",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
    )
    raw = f.to_dict()
    assert all(e.get("kind") != "remediation-artifact" for e in raw["evidences"])


def test_finding_rejects_wrong_class_uid() -> None:
    """The typed wrapper validates `class_uid == 2007`."""
    bad_payload = {
        "class_uid": 2003,  # F.3's class, not A.1's
        "finding_info": {"uid": "REM-K8S-001-x"},
    }
    with pytest.raises(ValueError, match="expected OCSF class_uid=2007"):
        RemediationFinding(bad_payload)


def test_finding_rejects_bad_finding_id() -> None:
    """The typed wrapper validates `REM_FINDING_ID_RE` even when the OCSF class is correct."""
    bad_payload: dict = {
        "class_uid": 2007,
        "finding_info": {"uid": "not-a-valid-rem-id"},
    }
    with pytest.raises(ValueError, match="finding_id must match"):
        RemediationFinding(bad_payload)


# ---------------------------- aggregate report ----------------------------


def test_report_aggregates_findings() -> None:
    rpt = RemediationReport(
        agent="remediation",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        mode=RemediationMode.RECOMMEND,
        scan_started_at=NOW,
        scan_completed_at=NOW,
    )
    f = build_remediation_finding(
        finding_id="REM-K8S-001-x",
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        outcome=RemediationOutcome.RECOMMENDED_ONLY,
        title="x",
        description="x",
        affected=[_resource()],
        detected_at=NOW,
        envelope=_envelope(),
    )
    rpt.add_finding(f)
    assert rpt.total == 1
    counts = rpt.count_by_outcome()
    assert counts["recommended_only"] == 1
    assert counts["executed_validated"] == 0


def test_report_mode_persists() -> None:
    """The report carries the mode it ran under — operators audit
    whether the run was recommend / dry-run / execute."""
    rpt = RemediationReport(
        agent="remediation",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        mode=RemediationMode.EXECUTE,
        scan_started_at=NOW,
        scan_completed_at=NOW,
    )
    payload = rpt.model_dump(mode="json")
    assert payload["mode"] == "execute"
