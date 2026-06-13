"""Remediation Agent driver — wires the 7-stage production-action pipeline.

A.1 is the **first "do" agent** in the platform (per ADR-007 / build roadmap).
Per the 2026-05-16 user direction "make it production action," this driver
ships all three operational tiers as `--mode` flags on a single agent:

    recommend (default; lowest blast radius)
        ↓
    dry-run (kubectl --dry-run=server)
        ↓
    execute (apply + rollback timer + post-validation)

Seven-stage pipeline:

    Stage 1: INGEST      — read detect-agent findings.json
    Stage 2: AUTHZ       — filter by allowlist + blast-radius cap
    Stage 3: GENERATE    — build per-finding RemediationArtifacts
    Stage 4: DRY-RUN     — kubectl --dry-run=server (dry-run + execute modes)
    Stage 5: EXECUTE     — kubectl patch (execute mode only)
    Stage 6: VALIDATE    — wait + re-run D.6 + decide rollback (execute only)
    Stage 7: ROLLBACK    — apply inverse patch if Stage 6 said so

Output contract (all under `contract.workspace/`):

    findings.json              — OCSF 2007 array; one record per attempted action
    artifacts/<corr_id>.json   — per-action kubectl-patch JSON (operator review)
    dry_run_diffs.json         — server-side diffs (dry-run + execute modes)
    execution_results.json     — per-action pre/post-patch state (execute mode)
    rollback_decisions.json    — per-action validate-pass/fail + rollback flag
    report.md                  — operator-facing markdown (dual-pin pattern)
    audit.jsonl                — F.6 hash-chained audit log (11 action types)

Cluster-access discipline mirrors D.6 v0.3 (3-way exclusion):

    --manifest-target              (no execute; just artifact generation; recommend mode only)
    --kubeconfig PATH              (explicit kubeconfig)
    --in-cluster                   (Pod-mounted ServiceAccount token)
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from charter import Charter, ToolNotPermitted, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from cloud_posture.schemas import AffectedResource
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from remediation import __version__ as agent_version
from remediation.audit import (
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    PipelineAuditor,
)
from remediation.authz import (
    Authorization,
    AuthorizationError,
    enforce_blast_radius,
    enforce_mode,
    filter_authorized_findings,
)
from remediation.generator import generate_artifacts
from remediation.invariants.action_allowlist import assert_action_allowlisted
from remediation.invariants.auto_mount_validation import (
    AutoMountValidationError,
    assert_auto_mount_validation,
)
from remediation.invariants.blast_radius import assert_blast_radius_capped
from remediation.invariants.default_recommend import assert_default_recommend
from remediation.invariants.dry_run_first import (
    STAGE_DRY_RUN,
    STAGE_EXECUTE,
    assert_dry_run_before_execute,
)
from remediation.invariants.idempotent_scoped import assert_idempotent_workspace_scoped
from remediation.invariants.privileged_authz import assert_privileged_action_extra_authz
from remediation.invariants.rollback_mandatory import assert_rollback_on_failed_validation
from remediation.invariants.tenant_scoped import assert_tenant_scoped
from remediation.invariants.tool_proxy import assert_tool_proxy_for_execute
from remediation.promotion import (
    PromotionTracker,
    effective_mode_for_stage,
)
from remediation.schemas import (
    RemediationActionType,
    RemediationArtifact,
    RemediationMode,
    RemediationOutcome,
    RemediationReport,
    build_remediation_finding,
)
from remediation.summarizer import render_summary
from remediation.tools.findings_reader import read_findings
from remediation.tools.kubectl_executor import (
    KubectlExecutorError,
    PatchResult,
    apply_patch,
)
from remediation.validator import (
    DetectorCallable,
    build_d6_detector,
    validate_outcome,
)
from remediation.validator import (
    rollback as run_rollback,
)

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    A.1 declares its tools to the Charter so per-tool budgets can be enforced.
    `read_findings` is a filesystem read; `apply_patch` makes kubectl calls
    (charged against the contract's `cloud_api_calls` budget).
    """
    reg = ToolRegistry()
    reg.register("read_findings", read_findings, version="0.1.0", cloud_calls=0)
    reg.register("apply_patch", apply_patch, version="0.1.0", cloud_calls=1)
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="remediation",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # reserved; not called in v0.1
    findings_path: Path | str,
    mode: RemediationMode = RemediationMode.RECOMMEND,
    authorization: Authorization | None = None,
    promotion: PromotionTracker | None = None,
    kubeconfig: Path | str | None = None,
    in_cluster: bool = False,
    cluster_namespace: str | None = None,
    detector_override: DetectorCallable | None = None,
    enable_execute: bool = False,
) -> RemediationReport:
    """Run the Remediation Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        findings_path: Path to a `findings.json` produced by a detect agent
            (D.6 / D.5 / F.3 / D.1). Required.
        mode: `RemediationMode.RECOMMEND` (default) / `DRY_RUN` / `EXECUTE`.
            Must be opted-in via `authorization` for dry-run + execute.
        authorization: An `Authorization` instance. Defaults to recommend-only
            with empty allowlist (the safest no-op). Operators load from
            `auth.yaml` via `Authorization.from_path()` and pass here.
        promotion: Optional `PromotionTracker` (v0.1.1) carrying the per-
            action-class graduation state. When provided, the agent applies
            the earned-autonomy pre-flight gate: each artifact's effective
            mode is downgraded to the action class's stage cap (Stage 1 →
            recommend / Stage 2 → dry_run / Stage 3+ → execute). When
            **all** artifacts would be downgraded and `mode != recommend`,
            the run halts with per-finding `REFUSED_PROMOTION_GATE`
            outcomes — the operator gets an unambiguous "blocked" signal
            instead of a quiet downgrade. When `promotion` is `None`
            (library default), the gate is skipped — used by tests and
            library callers who explicitly opt out of the safety contract.
            The CLI always passes a tracker (loaded from `--promotion` or
            the safe-by-default `persistent_root/promotion.yaml`).
            **Evidence accumulates regardless:** the audit chain emits
            `promotion.evidence.*` events on every successful stage, and
            the tracker (if provided) updates its in-memory counters so
            the caller can save the file at run end.
        kubeconfig: Optional explicit kubeconfig path. Mutually exclusive with
            `in_cluster` (3-way exclusion shared with `manifest-target` mode).
        in_cluster: When True, kubectl uses default discovery (Pod SA token).
            Mutually exclusive with `kubeconfig`.
        cluster_namespace: Scope for the post-validation D.6 re-run (Stage 6).
            Defaults to the namespace of each artifact when None.
        detector_override: Test hook — substitutes the validator's detector
            closure. Production runs leave this None.
        enable_execute: Phase C SS6 — the CLI kill-switch
            (``--i-understand-this-applies-patches-to-the-cluster``), now
            threaded into run() so the H1 dual-layer (WI-A8) is enforced
            INSIDE the agent, not only at the CLI. EXECUTE mode requires BOTH
            this flag AND ``authorization.mode_execute_authorized`` — either
            missing raises ``DefaultRecommendViolationError``. recommend /
            dry-run never require it (they do not mutate the cluster).

    Returns:
        The `RemediationReport`. Side effects: writes 7 output files to the
        contract workspace and emits a hash-chained audit log at `audit.jsonl`.
        When `promotion` is provided, the tracker is mutated in-place with
        accumulated evidence; the caller saves to YAML at the appropriate
        path.

    Raises:
        AuthorizationError: when the requested mode isn't opted-in OR the
            authorized findings exceed the blast-radius cap.
        ValueError: when both `kubeconfig` and `in_cluster` are supplied.
    """
    del llm_provider  # reserved

    if kubeconfig is not None and in_cluster:
        raise ValueError(
            "kubeconfig and in_cluster are mutually exclusive — pick one cluster-access mode"
        )

    # Phase C SS6: tenant scope is the privacy boundary (WI-A18) — a tenant only ever
    # remediates its own cluster. Asserted before any work.
    assert_tenant_scoped(contract)

    auth = authorization or Authorization.recommend_only()
    enforce_mode(auth, mode)
    # Phase C SS6: make the H1 dual-layer execute gate load-bearing in run() (WI-A8). enforce_mode
    # above checks the auth.yaml layer; this also requires the operator kill-switch (enable_execute)
    # for EXECUTE — so a caller cannot mutate the cluster by passing mode=execute with an authorized
    # auth.yaml but without the explicit flag. recommend / dry-run pass unconditionally.
    assert_default_recommend(
        mode,
        enable_execute_flag=enable_execute,
        auth_mode_authorized=auth.mode_execute_authorized,
    )

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)
        workspace = Path(contract.workspace)
        auditor = PipelineAuditor(workspace / "audit.jsonl", run_id=contract.delegation_id)

        auditor.run_started(
            mode=mode,
            findings_path=str(findings_path),
            authorized_actions=list(auth.authorized_actions),
            max_actions_per_run=auth.max_actions_per_run,
            rollback_window_sec=auth.rollback_window_sec,
        )

        # ---- Stage 1: INGEST ----
        all_findings = await ctx.call_tool("read_findings", path=findings_path)
        auditor.findings_ingested(count=len(all_findings), source_path=str(findings_path))

        # ---- Stage 2: AUTHZ ----
        authorized_findings, refused = filter_authorized_findings(auth, all_findings)
        for finding, reason in refused:
            auditor.action_refused(rule_id=finding.rule_id, reason=reason)
        report = RemediationReport(
            agent="remediation",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            mode=mode,
            scan_started_at=scan_started,
            scan_completed_at=scan_started,  # updated at the end
        )
        for finding, reason in refused:
            report.add_finding(
                _build_finding(
                    envelope=envelope,
                    artifact=None,
                    source_rule_id=finding.rule_id,
                    namespace=finding.namespace,
                    workload_kind=finding.workload_kind,
                    workload_name=finding.workload_name,
                    outcome=RemediationOutcome.REFUSED_UNAUTHORIZED,
                    description=reason,
                    sequence=len(report.findings) + 1,
                )
            )

        try:
            enforce_blast_radius(auth, len(authorized_findings))
        except AuthorizationError as exc:
            auditor.blast_radius_refused(
                requested=len(authorized_findings),
                cap=auth.max_actions_per_run,
            )
            # Add one synthetic finding so the OCSF report reflects the refusal.
            report.add_finding(
                _build_finding(
                    envelope=envelope,
                    artifact=None,
                    source_rule_id="(blast-radius-cap)",
                    namespace="(n/a)",
                    workload_kind="(n/a)",
                    workload_name="(n/a)",
                    outcome=RemediationOutcome.REFUSED_BLAST_RADIUS,
                    description=str(exc),
                    sequence=len(report.findings) + 1,
                )
            )
            authorized_findings = []  # halt; do not partial-apply

        # Phase C SS6: load-bearing blast-radius backstop (WI-A12 ceiling-50). enforce_blast_radius
        # above produces the graceful REFUSED_BLAST_RADIUS finding + empties the set on overflow;
        # this hard-asserts the surviving count never exceeds min(cap, 50) before we generate any
        # mutating artifact — a defence-in-depth catch for a future logic error in the cap path.
        assert_blast_radius_capped(len(authorized_findings), auth.max_actions_per_run)

        # ---- Stage 3: GENERATE ----
        artifacts = generate_artifacts(authorized_findings)
        for artifact in artifacts:
            auditor.artifact_generated(artifact)
        _write_artifact_files(workspace, artifacts)

        # ---- Stage 0: PROMOTION-GATE (v0.1.1, fires AFTER generate so action
        #              types are known). When promotion is None the gate is
        #              skipped (library opt-out). When provided, each artifact
        #              gets an effective mode = min(operator, stage_max). If
        #              ALL artifacts would be downgraded AND the operator
        #              asked for non-recommend, the whole run gets
        #              REFUSED_PROMOTION_GATE outcomes — unambiguous "your
        #              request was blocked" signal. If at least one artifact
        #              satisfies, per-finding downgrade applies and the
        #              downgraded ones emit their downgraded outcome
        #              (RECOMMENDED_ONLY / DRY_RUN_ONLY).
        effective_modes = _compute_effective_modes(artifacts, promotion, mode)
        if (
            promotion is not None
            and mode != RemediationMode.RECOMMEND
            and artifacts
            and all(em != mode for em in effective_modes.values())
        ):
            for artifact in artifacts:
                stage = promotion.stage_for(artifact.action_type)
                report.add_finding(
                    _build_finding(
                        envelope=envelope,
                        artifact=artifact,
                        source_rule_id=artifact.source_finding_uid,
                        namespace=artifact.namespace,
                        workload_kind=artifact.kind,
                        workload_name=artifact.name,
                        outcome=RemediationOutcome.REFUSED_PROMOTION_GATE,
                        description=(
                            f"action class {artifact.action_type.value} is at "
                            f"{stage.name} in this environment; --mode {mode.value} "
                            f"requires Stage {2 if mode == RemediationMode.DRY_RUN else 3}+. "
                            f"Promote via `remediation promotion advance` or "
                            f"lower the mode."
                        ),
                        sequence=len(report.findings) + 1,
                    )
                )
            artifacts = ()  # halt; do not partial-apply

        # ---- Stages 4-7 — one per artifact, in input order ----
        dry_run_diffs: list[dict[str, Any]] = []
        execution_results: list[dict[str, Any]] = []
        rollback_decisions: list[dict[str, Any]] = []

        for artifact in artifacts:
            # Phase C SS6: load-bearing action-allowlist guard (WI-A9). Stage 2's
            # filter_authorized_findings already dropped non-allowlisted findings (auditing each
            # refusal); this hard-asserts every artifact reaching the mutating stages is still
            # allowlisted — a defence-in-depth catch at the action boundary.
            assert_action_allowlisted(artifact.action_type, auth.authorized_actions)
            # Phase C SS6 (PR2): the two v0.2 action-specific safety guards, at the same boundary.
            # WI-A16 — a privileged action (disable-privileged-container) needs the SEPARATE
            # privileged_actions_authorized opt-in beyond the H2 allowlist.
            assert_privileged_action_extra_authz(artifact.action_type, auth.model_dump())
            # WI-A17 — disabling SA-token auto-mount must not break a workload that actively
            # consumes the token; hydrate the pod spec from the source manifest and validate.
            sa_name, containers = _auto_mount_context(artifact)
            assert_auto_mount_validation(
                action_type=artifact.action_type,
                service_account_name=sa_name,
                containers=containers,
            )
            # Phase C SS6 (PR3, WI-A13/H6): idempotent + workspace-scoped. The correlation_id must
            # be the deterministic hash-derived id (so re-running a finding never double-applies)
            # and the per-action artifact file must land inside the contract workspace.
            assert_idempotent_workspace_scoped(
                correlation_id=artifact.correlation_id,
                source_finding_id=artifact.source_finding_uid,
                artifact_path=workspace / "artifacts" / f"{artifact.correlation_id}.json",
                workspace_root=workspace,
            )
            outcome, description = await _process_artifact(
                ctx=ctx,
                artifact=artifact,
                effective_mode=effective_modes[artifact.correlation_id],
                auth=auth,
                kubeconfig=Path(kubeconfig) if kubeconfig else None,
                in_cluster=in_cluster,
                cluster_namespace=cluster_namespace,
                auditor=auditor,
                promotion=promotion,
                dry_run_diffs=dry_run_diffs,
                execution_results=execution_results,
                rollback_decisions=rollback_decisions,
                detector_override=detector_override,
            )
            report.add_finding(
                _build_finding(
                    envelope=envelope,
                    artifact=artifact,
                    source_rule_id=artifact.source_finding_uid,
                    namespace=artifact.namespace,
                    workload_kind=artifact.kind,
                    workload_name=artifact.name,
                    outcome=outcome,
                    description=description,
                    sequence=len(report.findings) + 1,
                )
            )

        # ---- HANDOFF — write outputs + close the run ----
        report.scan_completed_at = datetime.now(UTC)

        ctx.write_output("findings.json", report.model_dump_json(indent=2).encode("utf-8"))
        ctx.write_output("dry_run_diffs.json", json.dumps(dry_run_diffs, indent=2).encode("utf-8"))
        ctx.write_output(
            "execution_results.json",
            json.dumps(execution_results, indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "rollback_decisions.json",
            json.dumps(rollback_decisions, indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "report.md",
            render_summary(
                report,
                audit_head_hash=None,
                audit_tail_hash=auditor.tail_hash,
            ).encode("utf-8"),
        )

        auditor.run_completed(
            outcome_counts=report.count_by_outcome(),
            total_actions=report.total,
        )

        ctx.assert_complete()

    return report


# ---------------------------- per-artifact runner -------------------------


async def _process_artifact(
    *,
    ctx: Charter,
    artifact: RemediationArtifact,
    effective_mode: RemediationMode,
    auth: Authorization,
    kubeconfig: Path | None,
    in_cluster: bool,
    cluster_namespace: str | None,
    auditor: PipelineAuditor,
    promotion: PromotionTracker | None,
    dry_run_diffs: list[dict[str, Any]],
    execution_results: list[dict[str, Any]],
    rollback_decisions: list[dict[str, Any]],
    detector_override: DetectorCallable | None,
) -> tuple[RemediationOutcome, str]:
    """Run Stages 4-7 for a single artifact, returning the final outcome + description.

    `effective_mode` is the per-artifact mode after the promotion-gate
    downgrade — see `_compute_effective_modes`. The mode determines which
    stages fire (per the README mode/stage matrix). Outputs are appended
    to the three side-effect lists for the workspace files.

    On every successful stage that contributes to promotion evidence
    (Stage 1 artifact, Stage 4 dry-run success, Stage 6 validated, Stage 7
    rollback), the corresponding `promotion.evidence.*` audit entry is
    emitted AND `promotion.record_evidence` is called if a tracker was
    provided. The audit chain is the source of truth (safety-verification
    §3); the tracker is a derived cache.
    """
    workload_id = f"{artifact.namespace}/{artifact.name}"
    # Phase C SS6: per-artifact ordered stage log feeding assert_dry_run_before_execute (WI-A10).
    stage_history: list[str] = []

    # ---- Stage 4: DRY-RUN (skipped in recommend mode) ----
    if effective_mode == RemediationMode.RECOMMEND:
        _emit_promotion_evidence(
            auditor=auditor,
            promotion=promotion,
            artifact=artifact,
            event=ACTION_PROMOTION_EVIDENCE_STAGE1,
            workload=None,
        )
        return (
            RemediationOutcome.RECOMMENDED_ONLY,
            f"Artifact built for {artifact.action_type.value}; no execution in recommend mode.",
        )

    try:
        dry_run = await ctx.call_tool(
            "apply_patch",
            artifact=artifact,
            dry_run=True,
            kubeconfig=kubeconfig,
            fetch_state=False,
        )
    except KubectlExecutorError as exc:
        synthetic = _synthetic_failure_result(stderr=str(exc))
        auditor.dry_run_completed(artifact, synthetic)
        dry_run_diffs.append(_diff_record(artifact, synthetic))
        return (RemediationOutcome.DRY_RUN_FAILED, str(exc))

    auditor.dry_run_completed(artifact, dry_run)
    dry_run_diffs.append(_diff_record(artifact, dry_run))

    if not dry_run.succeeded:
        return (
            RemediationOutcome.DRY_RUN_FAILED,
            f"kubectl --dry-run=server failed (exit {dry_run.exit_code})",
        )

    # Phase C SS6: a successful server-side dry-run is recorded; this is the precondition the
    # dry-run-first invariant (WI-A10) checks before any execute is permitted below.
    stage_history.append(STAGE_DRY_RUN)

    # Successful dry-run is Stage-2 evidence.
    _emit_promotion_evidence(
        auditor=auditor,
        promotion=promotion,
        artifact=artifact,
        event=ACTION_PROMOTION_EVIDENCE_STAGE2,
        workload=None,
    )

    if effective_mode == RemediationMode.DRY_RUN:
        return (
            RemediationOutcome.DRY_RUN_ONLY,
            "Dry-run validation passed; no execution in dry-run mode.",
        )

    # ---- Stage 5: EXECUTE ----
    # Phase C SS6: make the dry-run-first (WI-A10) + tool-proxy (WI-A14) invariants load-bearing at
    # the mutation boundary. stage_history records "execute" then asserts a successful dry-run
    # preceded it; assert_tool_proxy_for_execute confirms the mutation routes through ctx.call_tool
    # (via_tool_proxy=True — the only path below).
    stage_history.append(STAGE_EXECUTE)
    assert_dry_run_before_execute(stage_history)
    assert_tool_proxy_for_execute(mode=effective_mode, via_tool_proxy=True)
    # C-1 hard gate: the live-mutation call routes through the charter so
    # permitted_tools, budget, and the charter audit chain all bind it. The
    # explicit pre-execute re-check is defense-in-depth — ctx.call_tool enforces
    # the whitelist itself, but stating it at the mutation boundary makes the
    # invariant impossible to miss for anyone editing this path (ADR-016).
    if "apply_patch" not in ctx.contract.permitted_tools:
        raise ToolNotPermitted(tool="apply_patch", permitted=list(ctx.contract.permitted_tools))
    try:
        execute = await ctx.call_tool(
            "apply_patch",
            artifact=artifact,
            dry_run=False,
            kubeconfig=kubeconfig,
            fetch_state=True,
        )
    except KubectlExecutorError as exc:
        synthetic = _synthetic_failure_result(stderr=str(exc))
        auditor.execute_failed(artifact, synthetic)
        execution_results.append(_diff_record(artifact, synthetic))
        return (RemediationOutcome.EXECUTE_FAILED, str(exc))

    if not execute.succeeded:
        auditor.execute_failed(artifact, execute)
        execution_results.append(_diff_record(artifact, execute))
        return (
            RemediationOutcome.EXECUTE_FAILED,
            f"kubectl patch failed (exit {execute.exit_code})",
        )

    auditor.execute_completed(artifact, execute)
    execution_results.append(_diff_record(artifact, execute))

    # ---- Stage 6: VALIDATE ----
    namespace_scope = cluster_namespace or artifact.namespace
    detector = detector_override or build_d6_detector(
        namespace=namespace_scope,
        kubeconfig=kubeconfig,
        in_cluster=in_cluster,
    )
    validation = await validate_outcome(
        artifact=artifact,
        source_rule_id=_finding_rule_from_artifact(artifact),
        detector=detector,
        rollback_window_sec=auth.rollback_window_sec,
    )
    auditor.validate_completed(artifact, validation)

    if validation.validated:
        # Phase C SS6: validation held → no rollback required (WI-A11 holds trivially).
        assert_rollback_on_failed_validation(requires_rollback=False, rollback_executed=False)
        rollback_decisions.append(
            {
                "correlation_id": artifact.correlation_id,
                "requires_rollback": False,
                "matched_findings_count": 0,
            }
        )
        # Validated execute is Stage-3 evidence; the workload id participates
        # in `stage3_distinct_workloads` (≥10 required for Stage 4).
        _emit_promotion_evidence(
            auditor=auditor,
            promotion=promotion,
            artifact=artifact,
            event=ACTION_PROMOTION_EVIDENCE_STAGE3,
            workload=workload_id,
        )
        return (
            RemediationOutcome.EXECUTED_VALIDATED,
            "Patch validated; original finding no longer detected.",
        )

    # ---- Stage 7: ROLLBACK ----
    # Routes through ctx.call_tool (same proxy/budget/audit surface as Stage-5
    # EXECUTE) — the rollback is a real cluster mutation (ADR-016 / WI-A14).
    rollback_result = await run_rollback(ctx, artifact, kubeconfig=kubeconfig)
    # Phase C SS6: validation failed → rollback is MANDATORY (WI-A11, no override). The inverse
    # patch was just executed above; assert the mandatory rollback actually ran.
    assert_rollback_on_failed_validation(requires_rollback=True, rollback_executed=True)
    auditor.rollback_completed(artifact, rollback_result)
    rollback_decisions.append(
        {
            "correlation_id": artifact.correlation_id,
            "requires_rollback": True,
            "matched_findings_count": len(validation.matched_findings),
            "rollback_succeeded": rollback_result.succeeded,
        }
    )
    # **Webhook attribution is a Phase-1c follow-up** (the rolled-back-path
    # xfail in `test_agent_kind_live.py`). Until that fixture lands, every
    # rollback counts as `unexpected_rollback` — penalises Stage-3 promotion
    # which is the deliberately-conservative default. This is named in
    # safety-verification §6 item 3 as a Stage-4 prerequisite.
    _emit_promotion_evidence(
        auditor=auditor,
        promotion=promotion,
        artifact=artifact,
        event=ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        workload=None,
    )
    return (
        RemediationOutcome.EXECUTED_ROLLED_BACK,
        f"Post-validation detected the rule still firing; "
        f"inverse patch applied (rollback exit {rollback_result.exit_code}).",
    )


# ---------------------------- promotion-gate helpers ----------------------


def _compute_effective_modes(
    artifacts: Iterable[RemediationArtifact],
    promotion: PromotionTracker | None,
    operator_mode: RemediationMode,
) -> dict[str, RemediationMode]:
    """Return a dict mapping `correlation_id -> effective_mode` for every artifact.

    When `promotion` is None (library opt-out), every artifact's effective
    mode is just the operator's mode — no downgrade. When provided, each
    artifact's mode is capped by the action class's stage via
    `effective_mode_for_stage`.
    """
    if promotion is None:
        return {a.correlation_id: operator_mode for a in artifacts}
    return {
        a.correlation_id: effective_mode_for_stage(
            operator_mode,
            promotion.stage_for(a.action_type),
        )
        for a in artifacts
    }


def _emit_promotion_evidence(
    *,
    auditor: PipelineAuditor,
    promotion: PromotionTracker | None,
    artifact: RemediationArtifact,
    event: str,
    workload: str | None,
) -> None:
    """Dual-emit one promotion evidence event: F.6 audit chain (always) +
    in-memory tracker (when provided).

    The audit chain is the source of truth — every successful stage's
    promotion evidence lands there regardless of whether the caller supplied
    a tracker. The reconciler (Task 6) can rebuild a `PromotionFile` from
    the chain even if no tracker was active during the run.

    The tracker's counters only mutate when a tracker is provided; this is
    the in-memory side for the same-run save path.
    """
    auditor.record_promotion_evidence(
        artifact.action_type,
        event=event,
        workload=workload,
        correlation_id=artifact.correlation_id,
    )
    if promotion is not None:
        promotion.record_evidence(
            artifact.action_type,
            event=event,
            workload=workload,
        )


# ---------------------------- helpers -------------------------------------


def _auto_mount_context(
    artifact: RemediationArtifact,
) -> tuple[str | None, tuple[Mapping[str, Any], ...]]:
    """Hydrate ``(service_account_name, containers)`` for the auto-mount guard (WI-A17).

    Non-auto-mount artifacts need no context (``assert_auto_mount_validation`` returns early), so an
    empty context is returned without touching the filesystem. For the auto-mount action the source
    manifest is read + the pod spec resolved. If the manifest is absent or unreadable the action is
    REFUSED (``AutoMountValidationError``) — disabling the SA-token mount without being able to
    verify the workload is not an active consumer is the unsafe direction (fail-closed).
    """
    if artifact.action_type != RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN:
        return (None, ())
    path = artifact.source_manifest_path
    if not path:
        raise AutoMountValidationError(
            "auto-mount disable requires the source manifest to verify no active token consumer; "
            "none was carried on the artifact — refused (WI-A17)."
        )
    try:
        manifest = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise AutoMountValidationError(
            f"cannot read source manifest {path!r} to verify auto-mount safety — refused (WI-A17)"
        ) from exc
    pod_spec = _resolve_pod_spec(manifest if isinstance(manifest, dict) else {}, artifact.kind)
    sa_name = pod_spec.get("serviceAccountName")
    containers = [
        c
        for c in (*(pod_spec.get("containers") or []), *(pod_spec.get("initContainers") or []))
        if isinstance(c, dict)
    ]
    return (str(sa_name) if sa_name else None, tuple(containers))


def _resolve_pod_spec(manifest: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    """Navigate a manifest dict to the pod spec by workload kind (mirrors k8s-posture's mapping).

    Pod → spec; CronJob → spec.jobTemplate.spec.template.spec; everything else (Deployment /
    StatefulSet / DaemonSet / ReplicaSet / Job) → spec.template.spec.
    """
    spec = manifest.get("spec")
    if not isinstance(spec, dict):
        return {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = spec.get("jobTemplate")
        tmpl = job.get("spec", {}).get("template") if isinstance(job, dict) else None
    else:
        tmpl = spec.get("template")
    inner = tmpl.get("spec") if isinstance(tmpl, dict) else None
    return inner if isinstance(inner, dict) else {}


def _finding_rule_from_artifact(artifact: RemediationArtifact) -> str:
    """Recover the source D.6 rule_id from an artifact's lineage field.

    The generator writes the source ManifestFinding's rule_id into
    `source_finding_uid` (see `generator.py`). For our re-detection scope,
    we just need the rule string back.
    """
    return artifact.source_finding_uid


_ACTION_TO_SOURCE_RULE: dict[RemediationActionType, str] = {
    RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT: "run-as-root",
    RemediationActionType.K8S_PATCH_RESOURCE_LIMITS: "missing-resource-limits",
    RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS: "read-only-root-fs-missing",
    RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS: "image-pull-policy-not-always",
    RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION: "allow-privilege-escalation",
}


def _build_finding(
    *,
    envelope: NexusEnvelope,
    artifact: RemediationArtifact | None,
    source_rule_id: str,
    namespace: str,
    workload_kind: str,
    workload_name: str,
    outcome: RemediationOutcome,
    description: str,
    sequence: int,
) -> Any:
    """Build one OCSF 2007 `RemediationFinding` for the report."""
    action_type = (
        artifact.action_type
        if artifact is not None
        else RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT  # fallback for refusals
    )
    finding_id = f"REM-K8S-{sequence:03d}-{_slug(source_rule_id, workload_name)}"
    title = (
        f"{outcome.value.replace('_', ' ').title()}: {action_type.value} on "
        f"{namespace}/{workload_kind}/{workload_name}"
    )
    affected = [
        AffectedResource(
            cloud="kubernetes",
            account_id=namespace or "n/a",
            region="cluster",
            resource_type=workload_kind or "n/a",
            resource_id=f"{namespace}/{workload_name}" if workload_name != "(n/a)" else "n/a",
            arn=(
                f"k8s://workload/{namespace}/{workload_kind}/{workload_name}"
                if workload_name != "(n/a)"
                else "k8s://refused"
            ),
        )
    ]
    return build_remediation_finding(
        finding_id=finding_id,
        action_type=action_type,
        outcome=outcome,
        title=title,
        description=description,
        affected=affected,
        detected_at=datetime.now(UTC),
        envelope=envelope,
        artifact=artifact,
    )


def _slug(*parts: str) -> str:
    """Build a lowercase slug for the REM finding_id context segment."""
    raw = "-".join(p for p in parts if p)
    out: list[str] = []
    for ch in raw.lower():
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        else:
            out.append("-")
    cleaned = "-".join(filter(None, "".join(out).split("-")))
    return cleaned or "action"


def _synthetic_failure_result(*, stderr: str) -> PatchResult:
    """Build a synthetic PatchResult for cases where kubectl couldn't even start
    (e.g. binary missing). Keeps the audit chain uniform regardless of why we
    failed."""
    return PatchResult(
        exit_code=127,  # POSIX convention for "command not found"
        stdout="",
        stderr=stderr,
        dry_run=False,
        pre_patch_hash=None,
        post_patch_hash=None,
        pre_patch_resource=None,
        post_patch_resource=None,
    )


def _diff_record(artifact: RemediationArtifact, result: PatchResult) -> dict[str, Any]:
    """Serialise a (artifact, PatchResult) tuple for the dry_run/execution JSON outputs."""
    return {
        "correlation_id": artifact.correlation_id,
        "action_type": artifact.action_type.value,
        "target": {
            "kind": artifact.kind,
            "namespace": artifact.namespace,
            "name": artifact.name,
        },
        "exit_code": result.exit_code,
        "succeeded": result.succeeded,
        "dry_run": result.dry_run,
        "pre_patch_hash": result.pre_patch_hash,
        "post_patch_hash": result.post_patch_hash,
        "stderr_head": result.stderr[:500] if result.stderr else "",
    }


def _write_artifact_files(workspace: Path, artifacts: Iterable[RemediationArtifact]) -> None:
    """Write one `artifacts/<correlation_id>.json` per artifact for operator review."""
    artifacts_dir = workspace / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        path = artifacts_dir / f"{artifact.correlation_id}.json"
        payload = {
            "action_type": artifact.action_type.value,
            "target": {
                "api_version": artifact.api_version,
                "kind": artifact.kind,
                "namespace": artifact.namespace,
                "name": artifact.name,
            },
            "patch_strategy": artifact.patch_strategy,
            "patch_body": artifact.patch_body,
            "inverse_patch_body": artifact.inverse_patch_body,
            "source_finding_uid": artifact.source_finding_uid,
            "correlation_id": artifact.correlation_id,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# `_ACTION_TO_SOURCE_RULE` is exported in case downstream consumers need the
# reverse mapping (action_type → rule_id) without re-walking the action_classes
# registry.
__all__ = [
    "_ACTION_TO_SOURCE_RULE",
    "build_registry",
    "run",
]
