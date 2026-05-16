"""Tests for `remediation.summarizer.render_summary` — operator-facing markdown."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cloud_posture.schemas import AffectedResource
from remediation.action_classes._common import wrap_container_patch
from remediation.schemas import (
    RemediationActionType,
    RemediationArtifact,
    RemediationMode,
    RemediationOutcome,
    RemediationReport,
    build_remediation_finding,
)
from remediation.summarizer import render_summary
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
    name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    correlation_id: str = "corr-test",
) -> RemediationArtifact:
    from k8s_posture.tools.manifests import ManifestFinding

    finding = ManifestFinding(
        rule_id="run-as-root",
        rule_title="Run As Root",
        severity="high",
        workload_kind="Deployment",
        workload_name=name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///x",
        detected_at=NOW,
    )
    leaf = {"securityContext": {"runAsNonRoot": True}}
    inverse_leaf = {"securityContext": {"runAsNonRoot": None}}
    return RemediationArtifact(
        action_type=action_type,
        api_version="apps/v1",
        kind="Deployment",
        namespace=namespace,
        name=name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid="CSPM-KUBERNETES-MANIFEST-001-x",
        correlation_id=correlation_id,
    )


def _build_report(
    *,
    mode: RemediationMode = RemediationMode.EXECUTE,
    entries: list[tuple[RemediationOutcome, RemediationArtifact, str]] | None = None,
) -> RemediationReport:
    """entries is a list of (outcome, artifact, finding_uid) tuples."""
    report = RemediationReport(
        agent="remediation",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        mode=mode,
        scan_started_at=NOW,
        scan_completed_at=NOW,
    )
    for i, (outcome, artifact, uid) in enumerate(entries or []):
        report.add_finding(
            build_remediation_finding(
                finding_id=uid,
                action_type=artifact.action_type,
                outcome=outcome,
                title=f"Action {i}",
                description="x",
                affected=[_resource()],
                detected_at=NOW,
                envelope=_envelope(),
                artifact=artifact,
            )
        )
    return report


# ---------------------------- empty / header ------------------------------


def test_empty_report_renders_header_and_zero_total() -> None:
    report = _build_report(mode=RemediationMode.RECOMMEND, entries=[])
    out = render_summary(report)
    assert "# Remediation Report" in out
    assert "Mode: **recommend**" in out
    assert "Total attempted actions: **0**" in out
    # No rollback / failure pins on an empty run.
    assert "Pinned: rollbacks" not in out
    assert "Pinned: failures" not in out


def test_report_header_includes_customer_and_run_id() -> None:
    report = _build_report()
    out = render_summary(report)
    assert "`cust_test`" in out
    assert "`run_001`" in out


def test_report_carries_mode_in_header() -> None:
    for mode in (RemediationMode.RECOMMEND, RemediationMode.DRY_RUN, RemediationMode.EXECUTE):
        report = _build_report(mode=mode)
        assert f"Mode: **{mode.value}**" in render_summary(report)


# ---------------------------- pinned: rollbacks ---------------------------


def test_rollback_pin_appears_when_any_action_rolled_back() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="ok"),
                "REM-K8S-001-ok",
            ),
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-002-rb",
            ),
        ]
    )
    out = render_summary(report)
    assert "Pinned: rollbacks (1)" in out
    # The rolled-back action's correlation_id appears in the pinned section.
    assert "`rb`" in out


def test_rollback_pin_lists_correlation_id_action_type_location() -> None:
    """Each pinned bullet identifies the artifact end-to-end."""
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(
                    correlation_id="corr-x",
                    name="legacy",
                    namespace="payments",
                ),
                "REM-K8S-007-rb-legacy",
            ),
        ]
    )
    out = render_summary(report)
    assert "`corr-x`" in out
    assert "`payments/Deployment/legacy`" in out
    assert "`remediation_k8s_patch_runAsNonRoot`" in out


def test_rollback_pin_appears_before_per_outcome_breakdown() -> None:
    """The dual-pin pattern: rollbacks must come first so operators see them
    before scrolling to the rollup."""
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-001-rb",
            )
        ]
    )
    out = render_summary(report)
    rollback_idx = out.index("Pinned: rollbacks")
    breakdown_idx = out.index("Per-outcome breakdown")
    assert rollback_idx < breakdown_idx


# ---------------------------- pinned: failures ----------------------------


def test_failure_pin_aggregates_dry_run_and_execute_failures() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTE_FAILED,
                _artifact(correlation_id="exec-fail"),
                "REM-K8S-001-ef",
            ),
            (
                RemediationOutcome.DRY_RUN_FAILED,
                _artifact(correlation_id="dr-fail"),
                "REM-K8S-002-dr",
            ),
        ]
    )
    out = render_summary(report)
    assert "Pinned: failures (2)" in out
    assert "`exec-fail`" in out
    assert "`dr-fail`" in out


def test_failure_pin_omitted_when_no_failures() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="ok"),
                "REM-K8S-001-ok",
            )
        ]
    )
    out = render_summary(report)
    assert "Pinned: failures" not in out


def test_failures_pin_appears_after_rollback_pin() -> None:
    """Ordering: rollbacks first (most-urgent — agent action reversed itself),
    failures second (kubectl path broken, no state change)."""
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-001-rb",
            ),
            (
                RemediationOutcome.EXECUTE_FAILED,
                _artifact(correlation_id="fail"),
                "REM-K8S-002-fail",
            ),
        ]
    )
    out = render_summary(report)
    assert out.index("Pinned: rollbacks") < out.index("Pinned: failures")


# ---------------------------- per-outcome breakdown -----------------------


def test_per_outcome_breakdown_counts_match_findings() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="v1"),
                "REM-K8S-001-v1",
            ),
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="v2"),
                "REM-K8S-002-v2",
            ),
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-003-rb",
            ),
            (
                RemediationOutcome.REFUSED_UNAUTHORIZED,
                _artifact(correlation_id="ref"),
                "REM-K8S-004-ref",
            ),
        ]
    )
    out = render_summary(report)
    assert "**executed_validated**: 2" in out
    assert "**executed_rolled_back**: 1" in out
    assert "**refused_unauthorized**: 1" in out
    # Outcomes with zero count are omitted (less clutter for operators).
    assert "**dry_run_failed**: 0" not in out


def test_per_outcome_orders_most_actionable_first() -> None:
    """executed_rolled_back / failed / refused come before the success outcomes —
    operators read the bad news first."""
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="ok"),
                "REM-K8S-001-ok",
            ),
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-002-rb",
            ),
        ]
    )
    out = render_summary(report)
    rolled_back_idx = out.index("**executed_rolled_back**: 1")
    validated_idx = out.index("**executed_validated**: 1")
    assert rolled_back_idx < validated_idx


# ---------------------------- per-action-class breakdown ------------------


def test_per_action_breakdown_lists_each_distinct_action_type() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(
                    action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
                    correlation_id="a",
                ),
                "REM-K8S-001-a",
            ),
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(
                    action_type=RemediationActionType.K8S_PATCH_RESOURCE_LIMITS,
                    correlation_id="b",
                ),
                "REM-K8S-002-b",
            ),
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(
                    action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
                    correlation_id="c",
                ),
                "REM-K8S-003-c",
            ),
        ]
    )
    out = render_summary(report)
    assert "Per-action-class breakdown" in out
    assert "**remediation_k8s_patch_runAsNonRoot**: 2" in out
    assert "**remediation_k8s_patch_resource_limits**: 1" in out


# ---------------------------- all actions ---------------------------------


def test_all_actions_section_groups_by_outcome() -> None:
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="ok"),
                "REM-K8S-001-ok",
            ),
            (
                RemediationOutcome.EXECUTED_ROLLED_BACK,
                _artifact(correlation_id="rb"),
                "REM-K8S-002-rb",
            ),
        ]
    )
    out = render_summary(report)
    assert "## All actions" in out
    assert "### executed_rolled_back (1)" in out
    assert "### executed_validated (1)" in out


# ---------------------------- audit chain footer --------------------------


def test_audit_chain_footer_included_when_hashes_supplied() -> None:
    report = _build_report()
    out = render_summary(
        report,
        audit_head_hash="head" * 16,  # 64-char fake hash
        audit_tail_hash="tail" * 16,
    )
    assert "## Audit chain" in out
    assert "headhead" in out  # head hash chunk
    assert "tailtail" in out
    assert "audit-agent query" in out  # F.6 query hint


def test_audit_chain_footer_omitted_when_hashes_missing() -> None:
    report = _build_report()
    out = render_summary(report)  # no hashes
    assert "## Audit chain" not in out


# ---------------------------- determinism --------------------------------


def test_render_summary_is_deterministic() -> None:
    """Same report → identical markdown across runs."""
    report = _build_report(
        entries=[
            (
                RemediationOutcome.EXECUTED_VALIDATED,
                _artifact(correlation_id="ok"),
                "REM-K8S-001-ok",
            )
        ]
    )
    first = render_summary(report, audit_head_hash="a", audit_tail_hash="b")
    second = render_summary(report, audit_head_hash="a", audit_tail_hash="b")
    assert first == second


# ---------------------------- output is a string with trailing newline ---


def test_output_is_string_with_single_trailing_newline() -> None:
    """`report.md` should be writable directly without operators needing to add a newline."""
    out = render_summary(_build_report())
    assert isinstance(out, str)
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


# Silence the pytest unused-import warning when no fixtures are used.
_ = pytest
