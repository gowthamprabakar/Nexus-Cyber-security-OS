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
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from cloud_posture.schemas import AffectedResource
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from remediation import __version__ as agent_version
from remediation.audit import PipelineAuditor
from remediation.authz import (
    Authorization,
    AuthorizationError,
    enforce_blast_radius,
    enforce_mode,
    filter_authorized_findings,
)
from remediation.generator import generate_artifacts
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
    kubeconfig: Path | str | None = None,
    in_cluster: bool = False,
    cluster_namespace: str | None = None,
    detector_override: DetectorCallable | None = None,
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
        kubeconfig: Optional explicit kubeconfig path. Mutually exclusive with
            `in_cluster` (3-way exclusion shared with `manifest-target` mode).
        in_cluster: When True, kubectl uses default discovery (Pod SA token).
            Mutually exclusive with `kubeconfig`.
        cluster_namespace: Scope for the post-validation D.6 re-run (Stage 6).
            Defaults to the namespace of each artifact when None.
        detector_override: Test hook — substitutes the validator's detector
            closure. Production runs leave this None.

    Returns:
        The `RemediationReport`. Side effects: writes 7 output files to the
        contract workspace and emits a hash-chained audit log at `audit.jsonl`.

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

    auth = authorization or Authorization.recommend_only()
    enforce_mode(auth, mode)

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
        all_findings = await read_findings(path=findings_path)
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

        # ---- Stage 3: GENERATE ----
        artifacts = generate_artifacts(authorized_findings)
        for artifact in artifacts:
            auditor.artifact_generated(artifact)
        _write_artifact_files(workspace, artifacts)

        # ---- Stages 4-7 — one per artifact, in input order ----
        dry_run_diffs: list[dict[str, Any]] = []
        execution_results: list[dict[str, Any]] = []
        rollback_decisions: list[dict[str, Any]] = []

        for artifact in artifacts:
            outcome, description = await _process_artifact(
                artifact=artifact,
                mode=mode,
                auth=auth,
                kubeconfig=Path(kubeconfig) if kubeconfig else None,
                in_cluster=in_cluster,
                cluster_namespace=cluster_namespace,
                auditor=auditor,
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
    artifact: RemediationArtifact,
    mode: RemediationMode,
    auth: Authorization,
    kubeconfig: Path | None,
    in_cluster: bool,
    cluster_namespace: str | None,
    auditor: PipelineAuditor,
    dry_run_diffs: list[dict[str, Any]],
    execution_results: list[dict[str, Any]],
    rollback_decisions: list[dict[str, Any]],
    detector_override: DetectorCallable | None,
) -> tuple[RemediationOutcome, str]:
    """Run Stages 4-7 for a single artifact, returning the final outcome + description.

    The mode determines which stages fire (per the README mode/stage matrix).
    Outputs are appended to the three side-effect lists for the workspace files.
    """
    # ---- Stage 4: DRY-RUN (skipped in recommend mode) ----
    if mode == RemediationMode.RECOMMEND:
        return (
            RemediationOutcome.RECOMMENDED_ONLY,
            f"Artifact built for {artifact.action_type.value}; no execution in recommend mode.",
        )

    try:
        dry_run = await apply_patch(
            artifact,
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

    if mode == RemediationMode.DRY_RUN:
        return (
            RemediationOutcome.DRY_RUN_ONLY,
            "Dry-run validation passed; no execution in dry-run mode.",
        )

    # ---- Stage 5: EXECUTE ----
    try:
        execute = await apply_patch(
            artifact,
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
        rollback_decisions.append(
            {
                "correlation_id": artifact.correlation_id,
                "requires_rollback": False,
                "matched_findings_count": 0,
            }
        )
        return (
            RemediationOutcome.EXECUTED_VALIDATED,
            "Patch validated; original finding no longer detected.",
        )

    # ---- Stage 7: ROLLBACK ----
    rollback_result = await run_rollback(artifact, kubeconfig=kubeconfig)
    auditor.rollback_completed(artifact, rollback_result)
    rollback_decisions.append(
        {
            "correlation_id": artifact.correlation_id,
            "requires_rollback": True,
            "matched_findings_count": len(validation.matched_findings),
            "rollback_succeeded": rollback_result.succeeded,
        }
    )
    return (
        RemediationOutcome.EXECUTED_ROLLED_BACK,
        f"Post-validation detected the rule still firing; "
        f"inverse patch applied (rollback exit {rollback_result.exit_code}).",
    )


# ---------------------------- helpers -------------------------------------


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
