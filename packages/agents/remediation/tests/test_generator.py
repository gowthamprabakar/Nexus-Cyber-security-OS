"""Tests for `remediation.generator` — Stage 3 of the pipeline."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.generator import generate_artifacts
from remediation.schemas import RemediationActionType

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    rule_id: str = "run-as-root",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity="high",
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


# ---------------------------- empty input ---------------------------------


def test_empty_findings_returns_empty_tuple() -> None:
    assert generate_artifacts([]) == ()


# ---------------------------- one-to-one mapping --------------------------


def test_one_finding_produces_one_artifact() -> None:
    artifacts = generate_artifacts([_finding(rule_id="run-as-root")])
    assert len(artifacts) == 1
    assert artifacts[0].action_type == RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT


@pytest.mark.parametrize(
    "rule_id,expected_action",
    [
        ("run-as-root", RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT),
        ("missing-resource-limits", RemediationActionType.K8S_PATCH_RESOURCE_LIMITS),
        ("read-only-root-fs-missing", RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS),
        (
            "image-pull-policy-not-always",
            RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        ),
        (
            "allow-privilege-escalation",
            RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION,
        ),
    ],
)
def test_each_v0_1_rule_maps_to_its_action(
    rule_id: str, expected_action: RemediationActionType
) -> None:
    """All 5 v0.1 D.6 rule_ids should produce an artifact of the corresponding action type."""
    artifacts = generate_artifacts([_finding(rule_id=rule_id)])
    assert len(artifacts) == 1
    assert artifacts[0].action_type == expected_action


# ---------------------------- defense in depth ----------------------------


def test_unmapped_rule_is_silently_skipped() -> None:
    """A finding for a rule_id with no v0.1 action class drops out of the pipeline.
    Authz already filters these, but the generator is defensive."""
    artifacts = generate_artifacts(
        [
            _finding(rule_id="run-as-root", workload_name="actionable"),
            _finding(rule_id="privileged-container", workload_name="unmapped"),
            _finding(rule_id="host-network", workload_name="also-unmapped"),
        ]
    )
    assert len(artifacts) == 1
    assert artifacts[0].name == "actionable"


# ---------------------------- order preservation --------------------------


def test_artifact_order_matches_input_order() -> None:
    """Determinism guarantee — feeding the same inputs in the same order produces the
    same artifact order. Downstream stages (DRY-RUN / EXECUTE / VALIDATE) and the
    audit chain depend on this for reproducibility."""
    findings = [
        _finding(rule_id="run-as-root", workload_name="a"),
        _finding(rule_id="missing-resource-limits", workload_name="b"),
        _finding(rule_id="run-as-root", workload_name="c"),
    ]
    artifacts = generate_artifacts(findings)
    assert [a.name for a in artifacts] == ["a", "b", "c"]


# ---------------------------- lineage -------------------------------------


def test_artifact_source_finding_uid_links_back_to_source_rule() -> None:
    """Each artifact carries the source finding's rule_id as `source_finding_uid` (the
    most stable identifier we have at the Stage-3 input level). The agent driver may
    overwrite this with a full OCSF 2003 finding_uid when it has the wrapped payload."""
    artifacts = generate_artifacts([_finding(rule_id="run-as-root")])
    assert artifacts[0].source_finding_uid == "run-as-root"


# ---------------------------- idempotency ---------------------------------


def test_same_input_produces_same_artifacts() -> None:
    """Idempotency: same input → same correlation_ids → same artifacts. Re-running
    A.1 on the same findings.json yields kubectl patches that are no-ops (strategic-
    merge-patch with the same patch body is idempotent)."""
    findings = [_finding(rule_id="run-as-root", workload_name="frontend")]
    first = generate_artifacts(findings)
    second = generate_artifacts(findings)
    assert first[0].correlation_id == second[0].correlation_id
    assert first[0].patch_body == second[0].patch_body


def test_different_containers_get_different_correlation_ids() -> None:
    """Patching `nginx` vs `sidecar` on the same workload yields distinct
    correlation_ids (the lineage records make each patch separately auditable)."""
    artifacts = generate_artifacts(
        [
            _finding(rule_id="run-as-root", container_name="nginx", workload_name="x"),
            _finding(rule_id="run-as-root", container_name="sidecar", workload_name="x"),
        ]
    )
    assert artifacts[0].correlation_id != artifacts[1].correlation_id


# ---------------------------- artifact shape ------------------------------


def test_artifact_has_both_patch_and_inverse() -> None:
    """The Stage-7 ROLLBACK depends on every artifact carrying its inverse_patch_body."""
    artifacts = generate_artifacts([_finding(rule_id="run-as-root")])
    assert artifacts[0].patch_body
    assert artifacts[0].inverse_patch_body
    # The forward and inverse bodies differ (otherwise rollback would be a no-op).
    assert artifacts[0].patch_body != artifacts[0].inverse_patch_body


def test_artifact_target_matches_finding() -> None:
    artifacts = generate_artifacts([_finding(workload_name="cache", namespace="staging")])
    a = artifacts[0]
    assert a.name == "cache"
    assert a.namespace == "staging"
    assert a.kind == "Deployment"
