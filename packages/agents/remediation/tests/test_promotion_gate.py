"""Task 5 driver-integration tests for the promotion pre-flight gate.

Covers:

- The 4 helper paths of `_compute_effective_modes` (no-tracker, no-downgrade,
  full-downgrade, mixed).
- All 12 stage x mode combinations producing the documented effective mode.
- Run-level "all downgraded" behaviour: every artifact gets
  REFUSED_PROMOTION_GATE outcome; the run completes without raising.
- Mixed-stage runs: per-finding split with each artifact getting the
  outcome of its effective mode (RECOMMENDED_ONLY / DRY_RUN_ONLY /
  EXECUTED_VALIDATED).
- Evidence emission: every successful stage emits the matching
  `promotion.evidence.*` audit entry; the tracker's counters mutate in
  lock-step when one is provided.
- Backward compat: `promotion=None` skips the gate entirely (existing
  17 agent tests in test_agent.py prove this; this file adds a
  smoke-test for the contract).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from k8s_posture.tools.manifests import ManifestFinding
from remediation import agent as agent_mod
from remediation.agent import _compute_effective_modes, run
from remediation.audit import (
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
)
from remediation.authz import Authorization
from remediation.generator import generate_artifacts
from remediation.promotion import (
    ActionClassPromotion,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
)
from remediation.schemas import (
    RemediationActionType,
    RemediationMode,
    RemediationOutcome,
)
from remediation.tools.kubectl_executor import PatchResult

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


# ---------------------------- fixtures ----------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_test",
        task="promotion-gate test",
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
        persistent_root=str(tmp_path / "persistent"),
        created_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _manifest(*, rule_id: str = "run-as-root", name: str = "frontend") -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity="high",
        workload_kind="Deployment",
        workload_name=name,
        namespace="production",
        container_name="nginx",
        manifest_path=f"cluster:///production/Deployment/{name}",
        detected_at=_NOW,
    )


def _tracker_at(stages: dict[RemediationActionType, PromotionStage]) -> PromotionTracker:
    """Build a tracker with each named action class pinned to a stage.

    For Stage > 1, synthesises the minimum sign-off chain needed for
    `ActionClassPromotion`'s "stage matches latest sign-off" invariant.
    """
    action_classes: dict[str, ActionClassPromotion] = {}
    for action_type, stage in stages.items():
        sign_offs: list[PromotionSignOff] = []
        cur = PromotionStage.STAGE_1
        while cur < stage:
            nxt = PromotionStage(int(cur) + 1)
            sign_offs.append(
                PromotionSignOff(
                    event_kind="advance",
                    operator="test",
                    timestamp=_NOW,
                    reason="test fixture",
                    from_stage=cur,
                    to_stage=nxt,
                )
            )
            cur = nxt
        action_classes[action_type.value] = ActionClassPromotion(
            action_type=action_type,
            stage=stage,
            sign_offs=sign_offs,
        )
    pfile = PromotionFile(
        cluster_id="test-cluster",
        created_at=_NOW,
        last_modified_at=_NOW,
        action_classes=action_classes,
    )
    return PromotionTracker(pfile)


def _auth_for_mode(mode: RemediationMode, *, actions: list[str] | None = None) -> Authorization:
    """Build an Authorization that permits the requested mode + 5 action classes."""
    if actions is None:
        actions = [t.value for t in RemediationActionType]
    return Authorization(
        mode_recommend_authorized=True,
        mode_dry_run_authorized=mode != RemediationMode.RECOMMEND,
        mode_execute_authorized=mode == RemediationMode.EXECUTE,
        authorized_actions=actions,
        max_actions_per_run=10,
        rollback_window_sec=60,
    )


def _result_ok(*, dry_run: bool = False) -> PatchResult:
    return PatchResult(
        exit_code=0,
        stdout="ok",
        stderr="",
        dry_run=dry_run,
        pre_patch_hash="a" * 64 if not dry_run else None,
        post_patch_hash="b" * 64 if not dry_run else None,
        pre_patch_resource={"kind": "Deployment"} if not dry_run else None,
        post_patch_resource={"kind": "Deployment", "patched": True} if not dry_run else None,
    )


def _patch_driver(
    monkeypatch: pytest.MonkeyPatch,
    *,
    findings: tuple[ManifestFinding, ...] = (),
    detector_output: tuple[ManifestFinding, ...] = (),
) -> None:
    """Substitute the read_findings / apply_patch / build_d6_detector hooks
    with deterministic test doubles. Mirrors the pattern in test_agent.py."""

    async def fake_read(*, path: Path | str) -> tuple[ManifestFinding, ...]:
        del path
        return findings

    async def fake_apply(artifact: Any, *, dry_run: bool, **_: Any) -> PatchResult:
        del artifact
        return _result_ok(dry_run=dry_run)

    async def fake_detect() -> tuple[ManifestFinding, ...]:
        return detector_output

    def fake_factory(*, namespace: str, kubeconfig: Path | None, in_cluster: bool) -> Any:
        del namespace, kubeconfig, in_cluster
        return fake_detect

    import remediation.validator as validator_mod
    from remediation.tools import kubectl_executor as kc_mod

    monkeypatch.setattr(agent_mod, "read_findings", fake_read)
    monkeypatch.setattr(agent_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(validator_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(kc_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
    monkeypatch.setattr(agent_mod, "build_d6_detector", fake_factory)


def _patch_driver_with_apply_spy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    findings: tuple[ManifestFinding, ...] = (),
    detector_output: tuple[ManifestFinding, ...] = (),
) -> list[dict[str, Any]]:
    """Like `_patch_driver` but records every `apply_patch` invocation in a
    list the caller can inspect. The list is the proof artefact for the
    "no cluster contact for refused findings" safety property.

    Each entry: `{"correlation_id": str, "dry_run": bool}`.
    """
    calls: list[dict[str, Any]] = []

    async def fake_read(*, path: Path | str) -> tuple[ManifestFinding, ...]:
        del path
        return findings

    async def fake_apply(artifact: Any, *, dry_run: bool, **_: Any) -> PatchResult:
        calls.append({"correlation_id": artifact.correlation_id, "dry_run": dry_run})
        return _result_ok(dry_run=dry_run)

    async def fake_detect() -> tuple[ManifestFinding, ...]:
        return detector_output

    def fake_factory(*, namespace: str, kubeconfig: Path | None, in_cluster: bool) -> Any:
        del namespace, kubeconfig, in_cluster
        return fake_detect

    import remediation.validator as validator_mod
    from remediation.tools import kubectl_executor as kc_mod

    monkeypatch.setattr(agent_mod, "read_findings", fake_read)
    monkeypatch.setattr(agent_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(validator_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(kc_mod, "apply_patch", fake_apply)
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
    monkeypatch.setattr(agent_mod, "build_d6_detector", fake_factory)
    return calls


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    import remediation.validator as validator_mod

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(validator_mod.asyncio, "sleep", _instant)


# ---------------------------- _compute_effective_modes ------------------


def test_compute_effective_modes_no_tracker_returns_operator_mode() -> None:
    """promotion=None preserves operator mode (backward compat)."""
    findings = (_manifest(),)
    artifacts = generate_artifacts(findings)
    modes = _compute_effective_modes(artifacts, None, RemediationMode.EXECUTE)
    assert all(m == RemediationMode.EXECUTE for m in modes.values())


def test_compute_effective_modes_downgrades_per_stage() -> None:
    """Per-action-class downgrade — Stage 1 ⇒ recommend, Stage 2 ⇒ dry_run."""
    findings = (
        _manifest(rule_id="run-as-root", name="a"),  # Stage 1 in tracker
        _manifest(rule_id="missing-resource-limits", name="b"),  # Stage 2 in tracker
        _manifest(rule_id="read-only-root-fs-missing", name="c"),  # Stage 3 in tracker
    )
    artifacts = generate_artifacts(findings)
    tracker = _tracker_at(
        {
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1,
            RemediationActionType.K8S_PATCH_RESOURCE_LIMITS: PromotionStage.STAGE_2,
            RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS: PromotionStage.STAGE_3,
        }
    )
    modes = _compute_effective_modes(artifacts, tracker, RemediationMode.EXECUTE)
    # Match by correlation_id order
    effective_list = [modes[a.correlation_id] for a in artifacts]
    assert effective_list == [
        RemediationMode.RECOMMEND,  # Stage 1 caps at recommend
        RemediationMode.DRY_RUN,  # Stage 2 caps at dry_run
        RemediationMode.EXECUTE,  # Stage 3 permits execute
    ]


# ---------------------------- stage x mode matrix -----------------------


@pytest.mark.parametrize(
    ("stage", "operator_mode", "expected"),
    [
        # Stage 1 caps at recommend regardless of operator request.
        (PromotionStage.STAGE_1, RemediationMode.RECOMMEND, RemediationMode.RECOMMEND),
        (PromotionStage.STAGE_1, RemediationMode.DRY_RUN, RemediationMode.RECOMMEND),
        (PromotionStage.STAGE_1, RemediationMode.EXECUTE, RemediationMode.RECOMMEND),
        # Stage 2 permits up to dry_run.
        (PromotionStage.STAGE_2, RemediationMode.RECOMMEND, RemediationMode.RECOMMEND),
        (PromotionStage.STAGE_2, RemediationMode.DRY_RUN, RemediationMode.DRY_RUN),
        (PromotionStage.STAGE_2, RemediationMode.EXECUTE, RemediationMode.DRY_RUN),
        # Stage 3 permits up to execute.
        (PromotionStage.STAGE_3, RemediationMode.RECOMMEND, RemediationMode.RECOMMEND),
        (PromotionStage.STAGE_3, RemediationMode.DRY_RUN, RemediationMode.DRY_RUN),
        (PromotionStage.STAGE_3, RemediationMode.EXECUTE, RemediationMode.EXECUTE),
        # Stage 4 also caps at execute (no per-invocation difference vs Stage 3).
        (PromotionStage.STAGE_4, RemediationMode.RECOMMEND, RemediationMode.RECOMMEND),
        (PromotionStage.STAGE_4, RemediationMode.DRY_RUN, RemediationMode.DRY_RUN),
        (PromotionStage.STAGE_4, RemediationMode.EXECUTE, RemediationMode.EXECUTE),
    ],
)
def test_stage_mode_matrix(
    stage: PromotionStage, operator_mode: RemediationMode, expected: RemediationMode
) -> None:
    """All 12 stage x mode combinations produce the documented effective mode."""
    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: stage})
    findings = (_manifest(rule_id="run-as-root"),)
    artifacts = generate_artifacts(findings)
    modes = _compute_effective_modes(artifacts, tracker, operator_mode)
    assert modes[artifacts[0].correlation_id] is expected


# ---------------------------- run-level all-downgraded gate -------------


@pytest.mark.asyncio
async def test_run_all_downgraded_emits_refused_promotion_gate_for_every_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Single Stage-1 action class + --mode dry_run = all-downgraded ⇒ every
    finding gets REFUSED_PROMOTION_GATE. The run completes without raising;
    no kubectl is invoked (stages 4-7 don't run for refused findings)."""
    findings = (_manifest(rule_id="run-as-root"),)
    _patch_driver(monkeypatch, findings=findings)

    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1})
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_for_mode(RemediationMode.DRY_RUN),
        promotion=tracker,
    )

    assert report.total == 1
    outcome = report.findings[0]["finding_info"]["analytic"]["name"]
    assert outcome == RemediationOutcome.REFUSED_PROMOTION_GATE.value


@pytest.mark.asyncio
async def test_run_all_downgraded_execute_mode_emits_refused_for_stage2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Stage-2 + --mode execute = all-downgraded (effective is dry_run, operator
    wanted execute, no satisfaction) ⇒ REFUSED_PROMOTION_GATE."""
    findings = (_manifest(rule_id="missing-resource-limits"),)
    _patch_driver(monkeypatch, findings=findings)

    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RESOURCE_LIMITS: PromotionStage.STAGE_2})
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
        promotion=tracker,
    )

    assert report.total == 1
    assert (
        report.findings[0]["finding_info"]["analytic"]["name"]
        == RemediationOutcome.REFUSED_PROMOTION_GATE.value
    )


@pytest.mark.asyncio
async def test_run_recommend_mode_never_triggers_promotion_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--mode recommend is the floor — every action class can satisfy it
    regardless of stage, so REFUSED_PROMOTION_GATE never fires."""
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings)

    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1})
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=_auth_for_mode(RemediationMode.RECOMMEND),
        promotion=tracker,
    )
    assert (
        report.findings[0]["finding_info"]["analytic"]["name"]
        == RemediationOutcome.RECOMMENDED_ONLY.value
    )


# ---------------------------- mixed-stage per-finding split -------------


@pytest.mark.asyncio
async def test_run_mixed_stages_emits_per_finding_split(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """3 findings at Stages 1/2/3 + --mode execute → 3 outcomes:
    RECOMMENDED_ONLY (downgrade) / DRY_RUN_ONLY (downgrade) /
    EXECUTED_VALIDATED (request satisfied)."""
    findings = (
        _manifest(rule_id="run-as-root", name="a"),  # Stage 1
        _manifest(rule_id="missing-resource-limits", name="b"),  # Stage 2
        _manifest(rule_id="read-only-root-fs-missing", name="c"),  # Stage 3
    )
    _patch_driver(monkeypatch, findings=findings, detector_output=())

    tracker = _tracker_at(
        {
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1,
            RemediationActionType.K8S_PATCH_RESOURCE_LIMITS: PromotionStage.STAGE_2,
            RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS: PromotionStage.STAGE_3,
        }
    )
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
        promotion=tracker,
    )

    outcomes = [f["finding_info"]["analytic"]["name"] for f in report.findings]
    assert outcomes == [
        RemediationOutcome.RECOMMENDED_ONLY.value,
        RemediationOutcome.DRY_RUN_ONLY.value,
        RemediationOutcome.EXECUTED_VALIDATED.value,
    ]


# ---------------------------- evidence emission -------------------------


def _audit_actions(workspace: Path) -> list[str]:
    audit = workspace / "audit.jsonl"
    return [
        json.loads(line)["action"]
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line
    ]


@pytest.mark.asyncio
async def test_evidence_stage1_emitted_for_recommend_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A successful recommend-mode run emits promotion.evidence.stage1."""
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings)
    contract = _contract(tmp_path)

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.RECOMMEND,
        authorization=_auth_for_mode(RemediationMode.RECOMMEND),
    )

    actions = _audit_actions(Path(contract.workspace))
    assert ACTION_PROMOTION_EVIDENCE_STAGE1 in actions


@pytest.mark.asyncio
async def test_evidence_stage2_emitted_after_successful_dry_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings)
    contract = _contract(tmp_path)

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_for_mode(RemediationMode.DRY_RUN),
    )

    actions = _audit_actions(Path(contract.workspace))
    assert ACTION_PROMOTION_EVIDENCE_STAGE2 in actions


@pytest.mark.asyncio
async def test_evidence_stage3_emitted_after_validated_execute(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings, detector_output=())  # validated
    contract = _contract(tmp_path)

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
    )

    actions = _audit_actions(Path(contract.workspace))
    assert ACTION_PROMOTION_EVIDENCE_STAGE3 in actions


@pytest.mark.asyncio
async def test_evidence_unexpected_rollback_emitted_on_rollback_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """In v0.1.1 (pre-webhook-attribution), every rollback counts as
    unexpected_rollback — the deliberately-conservative default until the
    mutating-admission-webhook fixture lands (top Phase-1c follow-up)."""
    finding = _manifest()
    # Detector still finds the rule post-patch ⇒ rollback fires.
    _patch_driver(monkeypatch, findings=(finding,), detector_output=(finding,))
    contract = _contract(tmp_path)

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
    )

    actions = _audit_actions(Path(contract.workspace))
    assert ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK in actions


@pytest.mark.asyncio
async def test_tracker_counters_mutate_when_supplied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When a tracker is supplied, its in-memory counters mutate alongside
    the audit-chain emissions. Caller can save() at run end."""
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings)
    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_2})
    contract = _contract(tmp_path)

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_for_mode(RemediationMode.DRY_RUN),
        promotion=tracker,
    )

    entry = tracker.file.action_classes["remediation_k8s_patch_runAsNonRoot"]
    assert entry.evidence.stage2_dry_runs == 1


@pytest.mark.asyncio
async def test_backward_compat_promotion_none_skips_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With promotion=None, the gate is skipped — single-finding execute
    mode behaves exactly as in v0.1 (no REFUSED_PROMOTION_GATE outcomes)."""
    findings = (_manifest(),)
    _patch_driver(monkeypatch, findings=findings, detector_output=())
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
        promotion=None,
    )
    assert (
        report.findings[0]["finding_info"]["analytic"]["name"]
        == RemediationOutcome.EXECUTED_VALIDATED.value
    )


# ---------------------------- description text -------------------------


@pytest.mark.asyncio
async def test_refused_promotion_gate_description_names_remedy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """REFUSED_PROMOTION_GATE description names the current stage and the
    remedy command (`remediation promotion advance`) — operator can act
    on the report.md without consulting external docs."""
    _patch_driver(monkeypatch, findings=(_manifest(),))
    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1})
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.DRY_RUN,
        authorization=_auth_for_mode(RemediationMode.DRY_RUN),
        promotion=tracker,
    )
    desc = report.findings[0]["finding_info"]["desc"]
    assert "STAGE_1" in desc
    assert "remediation promotion advance" in desc


# ---------------------------- control-flow proof: zero kubectl for refusals ----
#
# These two tests demonstrate, with the actual control flow (call-count
# spies on apply_patch, not prose), that the REFUSED_PROMOTION_GATE-outcome
# design preserves the safety property the plan's "raise before the Charter
# context" was meant to deliver:
#
#   (a) For any REFUSED finding, NO pipeline work occurs — zero apply_patch
#       invocations, zero cluster contact.
#   (b) In the partial-satisfaction path, each finding's cluster contact is
#       capped at its effective_mode at the entry to `_process_artifact`;
#       downgraded findings (Stage-1 under --mode execute) do zero kubectl
#       calls before returning RECOMMENDED_ONLY.
#
# These are the proof artefacts the design accepts as a documented
# improvement on the plan's original Q4. Without them, the divergence would
# be a relabel rather than a real safety equivalence.


@pytest.mark.asyncio
async def test_proof_refused_findings_invoke_zero_kubectl_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**Proof of (a):** in the all-downgraded path, every finding gets
    REFUSED_PROMOTION_GATE outcome AND apply_patch is never invoked.

    Control-flow trace: agent.run computes effective modes after Stage 3
    generate. The all-downgraded predicate fires, every artifact is
    emitted as a REFUSED_PROMOTION_GATE finding, and `artifacts = ()` halts
    the per-artifact loop BEFORE any `_process_artifact` call. The kubectl
    executor is never reached.
    """
    findings = (
        _manifest(rule_id="run-as-root", name="alpha"),
        _manifest(rule_id="run-as-root", name="beta"),
        _manifest(rule_id="run-as-root", name="gamma"),
    )
    apply_calls = _patch_driver_with_apply_spy(monkeypatch, findings=findings)

    tracker = _tracker_at({RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1})
    contract = _contract(tmp_path)

    report = await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,  # Stage-1 caps at recommend → all downgraded
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
        promotion=tracker,
    )

    # Every finding is REFUSED_PROMOTION_GATE.
    outcomes = [f["finding_info"]["analytic"]["name"] for f in report.findings]
    assert outcomes == [RemediationOutcome.REFUSED_PROMOTION_GATE.value] * 3, (
        f"expected 3 REFUSED_PROMOTION_GATE outcomes, got {outcomes}"
    )

    # **The proof:** apply_patch was never called. Zero cluster contact.
    assert apply_calls == [], (
        f"REFUSED findings must trigger zero kubectl calls; got {len(apply_calls)} "
        f"call(s): {apply_calls}. The gate is supposed to halt before Stages 4-7."
    )

    # No dry_run_diffs / execution_results / rollback_decisions files emitted
    # for refused findings either (each is empty since `artifacts = ()`).
    workspace = Path(contract.workspace)
    dry_run_diffs = json.loads((workspace / "dry_run_diffs.json").read_text())
    execution_results = json.loads((workspace / "execution_results.json").read_text())
    rollback_decisions = json.loads((workspace / "rollback_decisions.json").read_text())
    assert dry_run_diffs == []
    assert execution_results == []
    assert rollback_decisions == []


@pytest.mark.asyncio
async def test_proof_per_finding_split_caps_cluster_contact_at_effective_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**Proof of (b):** in the partial-satisfaction path, each finding's
    kubectl call count is exactly what its effective_mode permits — Stage-1
    artifacts trigger ZERO calls, Stage-2 artifacts trigger ONE call
    (dry-run), Stage-3 artifacts trigger TWO calls (dry-run + execute).

    Control-flow trace: `_compute_effective_modes` runs before the per-
    artifact loop, capping each artifact's mode. Inside `_process_artifact`,
    the first check is `if effective_mode == RECOMMEND: return RECOMMENDED_ONLY`
    — Stage-1 artifacts exit at that line with no apply_patch call. Stage-2
    artifacts pass the recommend check, invoke apply_patch(dry_run=True),
    then hit `if effective_mode == DRY_RUN: return DRY_RUN_ONLY` — exit
    after exactly one call. Stage-3 artifacts traverse all four stages.

    The downgrade is the gate. The cluster never sees a request the action
    class hasn't earned.
    """
    findings = (
        _manifest(rule_id="run-as-root", name="alpha"),  # → Stage 1
        _manifest(rule_id="missing-resource-limits", name="beta"),  # → Stage 2
        _manifest(rule_id="read-only-root-fs-missing", name="gamma"),  # → Stage 3
    )
    apply_calls = _patch_driver_with_apply_spy(
        monkeypatch,
        findings=findings,
        detector_output=(),  # validator says rule no longer fires → Stage-3 validated
    )

    tracker = _tracker_at(
        {
            RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: PromotionStage.STAGE_1,
            RemediationActionType.K8S_PATCH_RESOURCE_LIMITS: PromotionStage.STAGE_2,
            RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS: PromotionStage.STAGE_3,
        }
    )
    contract = _contract(tmp_path)

    # Pre-compute correlation_ids so we can attribute calls back to artifacts.
    artifacts = generate_artifacts(findings)
    stage1_corr = artifacts[0].correlation_id
    stage2_corr = artifacts[1].correlation_id
    stage3_corr = artifacts[2].correlation_id

    await run(
        contract=contract,
        findings_path=tmp_path / "findings.json",
        mode=RemediationMode.EXECUTE,
        authorization=_auth_for_mode(RemediationMode.EXECUTE),
        promotion=tracker,
    )

    stage1_calls = [c for c in apply_calls if c["correlation_id"] == stage1_corr]
    stage2_calls = [c for c in apply_calls if c["correlation_id"] == stage2_corr]
    stage3_calls = [c for c in apply_calls if c["correlation_id"] == stage3_corr]

    # Stage-1 artifact: effective_mode == RECOMMEND → returns immediately at
    # the `if effective_mode == RECOMMEND` check. Zero apply_patch calls.
    assert stage1_calls == [], (
        f"Stage-1 artifact (capped at recommend) must trigger zero kubectl calls; "
        f"got {stage1_calls}"
    )

    # Stage-2 artifact: effective_mode == DRY_RUN → one dry-run call, then
    # returns at the `if effective_mode == DRY_RUN` check. Exactly one call.
    assert len(stage2_calls) == 1, (
        f"Stage-2 artifact (capped at dry_run) must trigger exactly one "
        f"kubectl call; got {len(stage2_calls)}: {stage2_calls}"
    )
    assert stage2_calls[0]["dry_run"] is True, (
        f"Stage-2 artifact's single call must be a dry-run; got dry_run="
        f"{stage2_calls[0]['dry_run']}"
    )

    # Stage-3 artifact: effective_mode == EXECUTE → dry-run + execute (and
    # rollback if validation fails, but detector_output=() so validation
    # passes). Exactly two calls.
    assert len(stage3_calls) == 2, (
        f"Stage-3 artifact (validated execute path) must trigger exactly two "
        f"kubectl calls (dry-run + execute); got {len(stage3_calls)}: {stage3_calls}"
    )
    # First call is dry-run, second is execute.
    assert stage3_calls[0]["dry_run"] is True
    assert stage3_calls[1]["dry_run"] is False

    # Cross-check: total call count is 0 + 1 + 2 = 3. No silent extra contact.
    assert len(apply_calls) == 3, (
        f"total apply_patch calls must be exactly 3 across the three findings; "
        f"got {len(apply_calls)}: {apply_calls}"
    )
