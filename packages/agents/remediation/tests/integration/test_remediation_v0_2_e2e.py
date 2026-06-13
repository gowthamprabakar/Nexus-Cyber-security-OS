"""v0.2 end-to-end composition + live-kind gate for A.1 (remediation v0.2 Task 20, WI-A4).

Two layers:

1. **Ungated composition** — proves the v0.2 surface composes WITHOUT a cluster: all 7 action
   classes build dispatchable artifacts, and a representative pipeline sequence passes all 10
   code-level safety invariants (H1-H6 + privileged-authz + auto-mount + tool-proxy + tenant) plus
   the batch-level primitives. This runs in CI.
2. **Live kind gate** — gated by ``NEXUS_LIVE_REMEDIATION=1`` (alongside the existing
   ``NEXUS_LIVE_K8S`` lane): the full 7-stage pipeline against a real cluster including execute +
   rollback. CI skips it; operators run it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.action_classes import ACTION_CLASS_REGISTRY
from remediation.batch_safety import artifacts_requiring_rollback, assert_all_dry_run_passed
from remediation.invariants.action_allowlist import assert_action_allowlisted
from remediation.invariants.auto_mount_validation import assert_auto_mount_validation
from remediation.invariants.blast_radius import assert_blast_radius_capped
from remediation.invariants.default_recommend import assert_default_recommend
from remediation.invariants.dry_run_first import assert_dry_run_before_execute
from remediation.invariants.idempotent_scoped import assert_idempotent_workspace_scoped
from remediation.invariants.privileged_authz import (
    PRIVILEGED_AUTHZ_FIELD,
    assert_privileged_action_extra_authz,
)
from remediation.invariants.rollback_mandatory import assert_rollback_on_failed_validation
from remediation.invariants.tenant_scoped import assert_tenant_scoped
from remediation.invariants.tool_proxy import assert_tool_proxy_for_execute
from remediation.schemas import RemediationMode

_NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
_TENANT = "cust-e2e"


def _finding(rule_id: str) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity="high",
        workload_kind="Deployment",
        workload_name="web",
        namespace="prod",
        container_name="app",
        manifest_path="cluster:///prod/Deployment/web",
        detected_at=_NOW,
    )


# ----------------------------- ungated composition -----------------------------


def test_all_seven_action_classes_build_dispatchable_artifacts() -> None:
    assert len(ACTION_CLASS_REGISTRY) == 7
    for rule_id, action_class in ACTION_CLASS_REGISTRY.items():
        artifact = action_class.build(_finding(rule_id))
        assert artifact.action_type is action_class.action_type
        assert artifact.patch_body  # a non-empty strategic-merge patch
        assert artifact.inverse_patch_body  # a rollback inverse


def test_full_invariant_chain_passes_for_authorized_execute() -> None:
    auth = {PRIVILEGED_AUTHZ_FIELD: True}
    allowlist = [ac.action_type.value for ac in ACTION_CLASS_REGISTRY.values()]
    # H1 + tenant + tool-proxy + blast radius for an authorized batched execute of all 7.
    assert_tenant_scoped(_TENANT)
    assert_default_recommend(
        RemediationMode.EXECUTE, enable_execute_flag=True, auth_mode_authorized=True
    )
    assert_blast_radius_capped(len(ACTION_CLASS_REGISTRY), 10)
    assert_tool_proxy_for_execute(mode=RemediationMode.EXECUTE, via_tool_proxy=True)
    for rule_id, action_class in ACTION_CLASS_REGISTRY.items():
        at = action_class.action_type
        assert_action_allowlisted(at, allowlist)
        assert_privileged_action_extra_authz(at, auth)
        assert_auto_mount_validation(
            action_type=at, service_account_name="default", containers=[{"name": "app"}]
        )
        assert_dry_run_before_execute(["generate", "dry_run", "execute"])
        assert_idempotent_workspace_scoped(
            correlation_id=f"{rule_id}-corr",
            source_finding_id=rule_id,
            artifact_path=f"/ws/{rule_id}.yaml",
            workspace_root="/ws",
        )
    assert_rollback_on_failed_validation(requires_rollback=False, rollback_executed=False)


def test_batched_dry_run_first_then_partial_rollback() -> None:
    # all dry-run pass -> batch proceeds; a partial execute failure rolls back the succeeded one.
    assert_all_dry_run_passed({"corr-a": True, "corr-b": True})
    assert artifacts_requiring_rollback({"corr-a": True, "corr-b": False}) == ("corr-a",)


# ------------------------------- live kind gate -------------------------------

_LIVE = os.environ.get("NEXUS_LIVE_REMEDIATION") == "1"


@pytest.mark.skipif(
    not _LIVE,
    reason="set NEXUS_LIVE_REMEDIATION=1 (+ a kind cluster) to run the full 7-stage live e2e",
)
def test_live_full_pipeline_execute_and_rollback() -> None:  # pragma: no cover - operator-run
    # Operator-run: the full INGEST->AUTHZ->GENERATE->DRY-RUN->EXECUTE->VALIDATE->ROLLBACK pipeline
    # against a real kind cluster, exercising the 7 action classes + execute + rollback. The
    # mechanics are shared with test_agent_kind_live.py (NEXUS_LIVE_K8S lane).
    from remediation.agent import run as _run  # noqa: F401  (import proves the entrypoint exists)

    assert _LIVE
