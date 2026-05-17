"""Remediation Agent CLI.

Subcommand families:

- `remediation eval CASES_DIR` — run the eval suite at CASES_DIR via the
  eval-framework's `run_suite` against `RemediationEvalRunner`. Prints
  `<passed>/<total> passed` and exits non-zero on any failure.
- `remediation run --contract path/to/contract.yaml --findings path/to/findings.json
  --auth path/to/auth.yaml [--mode recommend|dry_run|execute]
  [--kubeconfig PATH | --in-cluster] [--cluster-namespace NS]
  [--rollback-window-sec INT]` — run the agent against an `ExecutionContract`
  with findings produced by a detect agent (D.6 today; D.5/F.3/D.1 later).
  Writes 7 output files to the contract workspace.
- `remediation promotion {status,init,advance,demote,reconcile}` (v0.1.1)
  — the operator-facing surface for the earned-autonomy pipeline.
  `status` is read-only; `init`, `advance`, `demote` mutate both
  `promotion.yaml` and the audit chain. `reconcile` rebuilds
  `promotion.yaml` from the audit chain (`--dry-run` for diff-only
  preview) and refuses to materialise Stage 4 in v0.1.1 — even when
  the chain claims Stage 4, the cache file stays at Stage 3 max.

Mutual-exclusion gates and mode-escalation gates surface as `click.UsageError`
(non-zero exit, but with a usage prompt rather than a stack trace).
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from remediation import __version__
from remediation.agent import run as agent_run
from remediation.audit import PipelineAuditor
from remediation.authz import Authorization, AuthorizationError
from remediation.eval_runner import RemediationEvalRunner
from remediation.promotion import (
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
)
from remediation.schemas import RemediationActionType, RemediationMode

_MODE_CHOICES = [m.value for m in RemediationMode]


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Remediation Agent — recommend / dry-run / execute K8s remediations."""


# ---------------------- eval ---------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the eval suite at CASES_DIR.

    Exits 0 when every case passes, 1 otherwise. Prints one line per failing
    case with the failure_reason and actuals from the runner.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, RemediationEvalRunner()))
    click.echo(f"{suite.passed}/{suite.total} passed")
    fail_count = 0
    for case in suite.cases:
        if not case.passed:
            click.echo(f"  FAIL {case.case_id}: {case.failure_reason} (actual={case.actuals})")
            fail_count += 1
    if fail_count:
        raise SystemExit(1)


# ---------------------- run ----------------------------------------------


@main.command("run")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
@click.option(
    "--findings",
    "findings_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a findings.json produced by a detect agent (D.6 today).",
)
@click.option(
    "--auth",
    "auth_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an authorization.yaml controlling mode flags, action allowlist, "
    "blast-radius cap, and rollback window. When omitted, defaults to the safest "
    "no-op (recommend-only mode, empty allowlist).",
)
@click.option(
    "--mode",
    "mode_str",
    type=click.Choice(_MODE_CHOICES, case_sensitive=False),
    default=RemediationMode.RECOMMEND.value,
    show_default=True,
    help="Operational tier. `recommend` generates artifacts only; `dry_run` adds "
    "kubectl --dry-run=server; `execute` applies for real with mandatory "
    "post-validation + rollback.",
)
@click.option(
    "--kubeconfig",
    "kubeconfig",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a kubeconfig for cluster access. Mutually exclusive "
    "with --in-cluster. Required for dry_run / execute modes (no live cluster "
    "in recommend mode).",
)
@click.option(
    "--in-cluster",
    "in_cluster",
    is_flag=True,
    default=False,
    help="Load cluster config from the Pod's mounted ServiceAccount token. "
    "Mutually exclusive with --kubeconfig. Use this when running the agent as a "
    "Pod inside the cluster being patched.",
)
@click.option(
    "--cluster-namespace",
    "cluster_namespace",
    type=str,
    default=None,
    help="Override the namespace scope for the post-validation D.6 re-run "
    "(Stage 6). Defaults to each artifact's own namespace.",
)
@click.option(
    "--rollback-window-sec",
    "rollback_window_sec",
    type=click.IntRange(min=60, max=1800),
    default=None,
    help="Override `rollback_window_sec` from auth.yaml (60-1800). The validator "
    "waits this long between apply and re-detect before deciding rollback.",
)
@click.option(
    "--i-understand-this-applies-patches-to-the-cluster",
    "enable_execute",
    is_flag=True,
    default=False,
    help="REQUIRED to pass `--mode execute`. Operational kill-switch independent "
    "of auth.yaml: even an over-broad `auth.yaml` cannot apply patches without "
    "this flag also being supplied at the command line. Default is OFF; "
    "`recommend` and `dry_run` modes do not require it. Until A.1's safety "
    "contract has been proven against a live cluster (gate G3 of the four-gate "
    "plan), this flag should remain unset in any environment that holds real "
    "workloads. See: docs/_meta/a1-safety-verification-2026-05-16.md.",
)
def run_cmd(
    contract_path: Path,
    findings_path: Path,
    auth_path: Path | None,
    mode_str: str,
    kubeconfig: Path | None,
    in_cluster: bool,
    cluster_namespace: str | None,
    rollback_window_sec: int | None,
    enable_execute: bool,
) -> None:
    """Run the Remediation Agent end-to-end."""
    mode = RemediationMode(mode_str.lower())

    if kubeconfig is not None and in_cluster:
        raise click.UsageError(
            "--kubeconfig and --in-cluster are mutually exclusive — pick one cluster-access mode"
        )

    if mode != RemediationMode.RECOMMEND and not (kubeconfig or in_cluster):
        raise click.UsageError(
            f"--mode {mode.value} requires cluster access — supply --kubeconfig or --in-cluster"
        )

    if mode == RemediationMode.EXECUTE and not enable_execute:
        raise click.UsageError(
            "--mode execute is locked OFF by default. Pass "
            "`--i-understand-this-applies-patches-to-the-cluster` to enable it. "
            "This flag is an operational kill-switch independent of auth.yaml: "
            "both layers must agree before the agent applies patches. "
            "`recommend` and `dry_run` modes do not require this flag — use one "
            "of those to preview the patches first."
        )

    auth = Authorization.from_path(auth_path) if auth_path else Authorization.recommend_only()
    if rollback_window_sec is not None:
        auth = auth.model_copy(update={"rollback_window_sec": rollback_window_sec})

    contract = load_contract(contract_path)

    try:
        report = asyncio.run(
            agent_run(
                contract=contract,
                findings_path=findings_path,
                mode=mode,
                authorization=auth,
                kubeconfig=kubeconfig,
                in_cluster=in_cluster,
                cluster_namespace=cluster_namespace,
            )
        )
    except AuthorizationError as exc:
        # Mode-escalation refusal surfaces as a usage error with the contract's
        # required opt-in field name in the message.
        raise click.UsageError(str(exc)) from exc

    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"mode: {report.mode.value}")
    click.echo(f"findings: {report.total}")
    counts = report.count_by_outcome()
    for outcome_name, count in counts.items():
        if count > 0:
            click.echo(f"  {outcome_name}: {count}")
    click.echo(f"workspace: {contract.workspace}")


# ---------------------- promotion subcommands (v0.1.1) -----------------

_ACTION_TYPE_CHOICES = [m.value for m in RemediationActionType]
_TO_STAGE_CHOICES_ADVANCE = ["stage_2", "stage_3", "stage_4"]
_TO_STAGE_CHOICES_DEMOTE = ["stage_1", "stage_2", "stage_3"]


def _parse_stage(label: str) -> PromotionStage:
    """Parse `stage_N` (case-insensitive) into a `PromotionStage` enum."""
    return PromotionStage[label.upper()]


def _default_operator() -> str:
    """Identifier for the human running this CLI invocation.

    Resolution order: `$NEXUS_OPERATOR` (explicit override) → `$USER`
    (Unix conventional) → `unknown`. The operator can always override at
    the CLI with `--operator NAME`.
    """
    return os.environ.get("NEXUS_OPERATOR") or os.environ.get("USER") or "unknown"


def _stage4_refusal_message(action_type_value: str) -> str:
    """The Stage-3 → Stage-4 refusal text — pinned to safety-verification §6."""
    return (
        f"refusing to advance {action_type_value} to Stage 4: this version of A.1 "
        f"holds Stage 4 globally closed until two Phase-1c prerequisites land:\n"
        f"  (1) safety-verification §6 item 3 — the rolled-back-path webhook fixture "
        f"(test_execute_rolled_back_against_live_cluster currently xfails);\n"
        f"  (2) safety-verification §6 item 4 — ≥4 weeks of customer Stage-3 evidence "
        f"without unexpected rollbacks.\n"
        f"Until both are recorded, Stage 4 stays unreachable. Run Stage 3 in production "
        f"and accumulate evidence; the gate lifts when the prerequisites lift."
    )


@main.group("promotion")
def promotion_group() -> None:
    """Per-action-class graduation tracking (earned-autonomy pipeline).

    The CLI surface for safety-verification §3 promotion tracking. Every
    mutation (init/advance/demote) writes to BOTH `promotion.yaml`
    (the operator-readable cache) AND the audit chain (the F.6 source of
    truth — the reconciler in Task 8 can rebuild the cache from the
    chain). `status` is read-only.
    """


@promotion_group.command("status")
@click.option(
    "--promotion",
    "promotion_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to promotion.yaml.",
)
def promotion_status_cmd(promotion_path: Path) -> None:
    """Print per-action-class state and any proposed promotions."""
    tracker = PromotionTracker.from_path(promotion_path)
    if tracker is None:
        click.echo(
            f"no promotion.yaml at {promotion_path}; run `remediation promotion init` first.",
            err=True,
        )
        raise SystemExit(1)

    click.echo(f"cluster_id:       {tracker.file.cluster_id}")
    click.echo(f"schema_version:   {tracker.file.schema_version}")
    click.echo(f"last_modified_at: {tracker.file.last_modified_at.isoformat()}")
    click.echo("")

    if not tracker.file.action_classes:
        click.echo("(no action classes tracked yet — every action defaults to Stage 1)")
    else:
        click.echo(f"{'action_class':<55} {'stage':<10} {'evidence'}")
        click.echo("-" * 110)
        for key, entry in tracker.file.action_classes.items():
            ev = entry.evidence
            evidence_str = (
                f"s1={ev.stage1_artifacts} s2={ev.stage2_dry_runs} "
                f"s3={ev.stage3_executes} consec={ev.stage3_consecutive_executes} "
                f"rb={ev.stage3_unexpected_rollbacks} "
                f"workloads={len(ev.stage3_distinct_workloads)}"
            )
            click.echo(f"{key:<55} {entry.stage.name:<10} {evidence_str}")

    proposals = tracker.propose_promotions()
    if proposals:
        click.echo("")
        click.echo("Proposed promotions:")
        for p in proposals:
            click.echo(f"  {p.action_type.value}: {p.from_stage.name} → {p.to_stage.name}")
            click.echo(f"    {p.reason}")


@promotion_group.command("init")
@click.option(
    "--promotion",
    "promotion_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path where promotion.yaml will be written. Must not already exist.",
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path to the promotion audit log. Appended to (created if absent).",
)
@click.option(
    "--cluster-id",
    required=True,
    help="Operator-supplied cluster label (e.g. 'prod-eu-1'). Surfaces in "
    "audit logs and dashboards to disambiguate dev/staging/prod files.",
)
@click.option(
    "--action-class",
    "action_classes",
    type=click.Choice(_ACTION_TYPE_CHOICES),
    multiple=True,
    help="Action classes to register at Stage 1 (repeat for multiple). "
    "Defaults to all v0.1 action classes.",
)
def promotion_init_cmd(
    promotion_path: Path,
    audit_path: Path,
    cluster_id: str,
    action_classes: tuple[str, ...],
) -> None:
    """Initialise a fresh promotion.yaml with action classes at Stage 1.

    Refuses to overwrite an existing file — use `remediation promotion reconcile`
    (Task 8) to rebuild from the audit chain instead.
    """
    if promotion_path.exists():
        raise click.UsageError(
            f"{promotion_path} already exists; refusing to overwrite. "
            f"Use `remediation promotion reconcile` to rebuild from the "
            f"audit chain, or delete the file first if you really mean to "
            f"start fresh (you will lose accumulated state)."
        )

    chosen = list(action_classes) if action_classes else list(_ACTION_TYPE_CHOICES)

    # Build a tracker pre-populated at Stage 1.
    tracker = PromotionTracker.empty(cluster_id=cluster_id)
    from remediation.promotion import ActionClassPromotion

    for ac in chosen:
        tracker.file.action_classes[ac] = ActionClassPromotion(
            action_type=RemediationActionType(ac),
        )
    tracker.save(promotion_path)

    auditor = PipelineAuditor(audit_path, run_id=f"promotion-init-{_now_iso()}")
    auditor.record_promotion_init(cluster_id=cluster_id, action_classes=chosen)

    click.echo(f"promotion.yaml created: {promotion_path}")
    click.echo(f"audit entry written:    {audit_path}")
    click.echo(f"cluster_id:             {cluster_id}")
    click.echo(f"action classes (Stage 1): {len(chosen)}")
    for ac in chosen:
        click.echo(f"  - {ac}")


@promotion_group.command("advance")
@click.option(
    "--promotion",
    "promotion_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Promotion audit log path (appended to).",
)
@click.option(
    "--action",
    "action_type_str",
    type=click.Choice(_ACTION_TYPE_CHOICES),
    required=True,
    help="Action class to advance.",
)
@click.option(
    "--to",
    "to_stage_str",
    type=click.Choice(_TO_STAGE_CHOICES_ADVANCE, case_sensitive=False),
    required=True,
    help="Target stage. Must be exactly current+1 (no skipping).",
)
@click.option(
    "--reason",
    required=True,
    help="Free-text justification. Appears in the audit log and promotion.yaml.",
)
@click.option(
    "--operator",
    default=None,
    help="Operator identifier. Defaults to $NEXUS_OPERATOR or $USER.",
)
def promotion_advance_cmd(
    promotion_path: Path,
    audit_path: Path,
    action_type_str: str,
    to_stage_str: str,
    reason: str,
    operator: str | None,
) -> None:
    """Advance an action class by one stage with a signed sign-off."""
    _apply_transition(
        kind="advance",
        promotion_path=promotion_path,
        audit_path=audit_path,
        action_type_str=action_type_str,
        to_stage_str=to_stage_str,
        reason=reason,
        operator=operator,
    )


@promotion_group.command("demote")
@click.option(
    "--promotion",
    "promotion_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--action",
    "action_type_str",
    type=click.Choice(_ACTION_TYPE_CHOICES),
    required=True,
)
@click.option(
    "--to",
    "to_stage_str",
    type=click.Choice(_TO_STAGE_CHOICES_DEMOTE, case_sensitive=False),
    required=True,
    help="Target stage. Must be strictly less than the current stage.",
)
@click.option(
    "--reason",
    required=True,
    help="Free-text justification. Required for the audit trail of any demotion.",
)
@click.option(
    "--operator",
    default=None,
)
def promotion_demote_cmd(
    promotion_path: Path,
    audit_path: Path,
    action_type_str: str,
    to_stage_str: str,
    reason: str,
    operator: str | None,
) -> None:
    """Demote an action class to a lower stage after an incident or regression."""
    _apply_transition(
        kind="demote",
        promotion_path=promotion_path,
        audit_path=audit_path,
        action_type_str=action_type_str,
        to_stage_str=to_stage_str,
        reason=reason,
        operator=operator,
    )


def _apply_transition(
    *,
    kind: str,
    promotion_path: Path,
    audit_path: Path,
    action_type_str: str,
    to_stage_str: str,
    reason: str,
    operator: str | None,
) -> None:
    """Shared implementation for `advance` and `demote`."""
    tracker = PromotionTracker.from_path(promotion_path)
    if tracker is None:
        raise click.UsageError(
            f"{promotion_path} does not exist; run `remediation promotion init` first."
        )

    action_type = RemediationActionType(action_type_str)
    to_stage = _parse_stage(to_stage_str)
    current_stage = tracker.stage_for(action_type)
    operator_name = operator or _default_operator()

    # Direction checks (Pydantic will also catch these on PromotionSignOff
    # construction, but the CLI's error message is more actionable).
    if kind == "advance":
        if to_stage <= current_stage:
            raise click.UsageError(
                f"{action_type.value} is already at {current_stage.name}; "
                f"--to {to_stage.name.lower()} is not an advance. To rerun a "
                f"prior advance use `remediation promotion reconcile` to "
                f"verify the chain state."
            )
        if int(to_stage) != int(current_stage) + 1:
            next_stage = PromotionStage(int(current_stage) + 1)
            raise click.UsageError(
                f"advance must move exactly +1 stage (no skipping); "
                f"{action_type.value} is currently at {current_stage.name}, "
                f"the next legal target is --to {next_stage.name.lower()}."
            )
        # Global Stage-3 → Stage-4 gate (safety-verification §6 items 3+4).
        if to_stage == PromotionStage.STAGE_4:
            raise click.UsageError(_stage4_refusal_message(action_type.value))
    else:  # demote
        if to_stage >= current_stage:
            raise click.UsageError(
                f"demote must move to a strictly lower stage; "
                f"{action_type.value} is currently at {current_stage.name}, "
                f"--to {to_stage.name.lower()} is not lower."
            )

    signoff = PromotionSignOff(
        event_kind=kind,  # type: ignore[arg-type]
        operator=operator_name,
        timestamp=datetime.now(UTC),
        reason=reason,
        from_stage=current_stage,
        to_stage=to_stage,
    )
    tracker.apply_signoff(action_type, signoff)
    tracker.save(promotion_path)

    auditor = PipelineAuditor(audit_path, run_id=f"promotion-{kind}-{_now_iso()}")
    auditor.record_promotion_transition(action_type, signoff)

    click.echo(
        f"{action_type.value}: {current_stage.name} → {to_stage.name} ({kind} by {operator_name})"
    )
    click.echo(f"reason: {reason}")
    click.echo(f"promotion.yaml updated: {promotion_path}")
    click.echo(f"audit entry written:    {audit_path}")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# ---------------------- promotion reconcile (v0.1.1 Task 8) -----------


@promotion_group.command("reconcile")
@click.option(
    "--promotion",
    "promotion_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path to promotion.yaml. Will be created if absent; overwritten if "
    "present (use --dry-run to preview).",
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the audit chain (audit.jsonl). Read for replay, then "
    "appended-to with the reconcile.completed entry.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the diff vs the existing promotion.yaml instead of writing. "
    "No audit entry is emitted in dry-run mode.",
)
@click.option(
    "--cluster-id",
    default="default",
    show_default=True,
    help="cluster_id used when the audit chain does not contain a promotion.init.applied event.",
)
def promotion_reconcile_cmd(
    promotion_path: Path,
    audit_path: Path,
    dry_run: bool,
    cluster_id: str,
) -> None:
    """Rebuild promotion.yaml from the audit chain.

    The audit chain is the F.6 source of truth (safety-verification §3);
    promotion.yaml is the operator-readable cache. This command replays the
    chain via `remediation.promotion.replay` and writes the canonical
    PromotionFile back to disk.

    **Stage-4 gate.** If the replayed state would materialize any action
    class at Stage 4, this command refuses with the two Phase-1c
    prerequisites from safety-verification §6 (rolled-back-path webhook
    fixture + ≥4 weeks customer Stage-3 evidence). The refusal is itself
    an audited event so forensics can find it in the chain.
    """
    from charter.audit import AuditEntry

    from remediation.promotion import ReplayError, replay

    # Read the audit chain (only promotion.* entries drive state, but the
    # full chain is preserved in the audit log).
    entries: list[AuditEntry] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(AuditEntry.from_json(line))
    promotion_entries_count = sum(1 for e in entries if e.action.startswith("promotion."))

    # Replay → canonical state.
    try:
        reconstructed = replay(entries, default_cluster_id=cluster_id)
    except ReplayError as exc:
        raise click.UsageError(
            f"reconcile failed: chain is inconsistent. {exc}\n"
            f"Investigate via `audit-agent query --path {audit_path}`."
        ) from exc

    # Stage-4 gate: refuse to materialize Stage 4 in v0.1.1.
    stage_4_classes = sorted(
        ac
        for ac, entry in reconstructed.action_classes.items()
        if entry.stage is PromotionStage.STAGE_4
    )
    if stage_4_classes:
        refusal_reason = _stage4_reconcile_refusal_text(stage_4_classes)
        click.echo(refusal_reason, err=True)
        # The refusal is itself an audited event.
        auditor = PipelineAuditor(audit_path, run_id=f"promotion-reconcile-refused-{_now_iso()}")
        auditor.record_promotion_reconcile(
            chain_entries_replayed=promotion_entries_count,
            state_changes={},
            refused=True,
            refusal_reason=refusal_reason,
        )
        raise SystemExit(1)

    # Compute the diff vs the existing promotion.yaml (if any).
    existing_tracker = PromotionTracker.from_path(promotion_path)
    existing_file = existing_tracker.file if existing_tracker else None
    state_changes = _compute_reconcile_diff(existing_file, reconstructed)

    if dry_run:
        click.echo("--- reconcile dry-run ---")
        click.echo(f"audit entries replayed: {promotion_entries_count} promotion.* events")
        if not state_changes:
            click.echo("no state changes — promotion.yaml already matches the chain.")
        else:
            click.echo(f"would update {len(state_changes)} action class(es):")
            for ac, changes in state_changes.items():
                click.echo(f"  {ac}:")
                for field, change in changes.items():
                    click.echo(f"    {field}: {change}")
        click.echo("(dry-run — promotion.yaml NOT modified, no audit entry emitted)")
        return

    # Write the rebuilt file. PromotionTracker.save() handles the atomic
    # tempfile-rename, parent-dir creation, and last_modified_at update.
    PromotionTracker(reconstructed).save(promotion_path)

    # Emit the reconcile.completed audit entry.
    auditor = PipelineAuditor(audit_path, run_id=f"promotion-reconcile-{_now_iso()}")
    auditor.record_promotion_reconcile(
        chain_entries_replayed=promotion_entries_count,
        state_changes=state_changes,
    )

    click.echo(f"reconcile complete; {promotion_entries_count} promotion.* entries replayed")
    click.echo(f"promotion.yaml updated: {promotion_path}")
    if state_changes:
        click.echo(f"state changes: {len(state_changes)} action class(es) updated")
        for ac, changes in state_changes.items():
            click.echo(f"  {ac}: {changes}")
    else:
        click.echo("(no state changes — promotion.yaml already matched the chain)")


def _stage4_reconcile_refusal_text(action_classes: list[str]) -> str:
    """The Stage-4 reconcile refusal — pinned to safety-verification §6."""
    bullet_list = "\n".join(f"  - {ac}" for ac in action_classes)
    return (
        f"reconcile refused: the audit chain materialises "
        f"{len(action_classes)} action class(es) at Stage 4, but v0.1.1 holds "
        f"Stage 4 globally closed (safety-verification §6 items 3+4):\n"
        f"  (1) the rolled-back-path webhook fixture has not landed "
        f"(test_execute_rolled_back_against_live_cluster currently xfails);\n"
        f"  (2) ≥4 weeks of customer Stage-3 evidence has not accumulated.\n"
        f"\nAffected action classes:\n"
        f"{bullet_list}\n"
        f"\nIf the chain contains a Stage-4 transition from a future version of A.1, "
        f"upgrade to that version before reconciling. If the chain is corrupted or "
        f"hand-edited, investigate via "
        f"`audit-agent query --action promotion.advance.applied`."
    )


def _compute_reconcile_diff(
    old: PromotionFile | None,
    new: PromotionFile,
) -> dict[str, dict[str, str]]:
    """Compute a per-action-class diff between two PromotionFiles.

    Returns a dict keyed by action_type whose values describe what changed:
    `{"stage": "STAGE_1 → STAGE_2", "evidence": "counters updated", ...}`.
    Action classes whose state is identical between old and new are absent
    from the result.
    """
    changes: dict[str, dict[str, str]] = {}
    old_classes = old.action_classes if old else {}

    for ac, new_entry in new.action_classes.items():
        old_entry = old_classes.get(ac)
        if old_entry is None:
            changes[ac] = {"appeared": f"now at {new_entry.stage.name}"}
            continue
        diff: dict[str, str] = {}
        if old_entry.stage != new_entry.stage:
            diff["stage"] = f"{old_entry.stage.name} -> {new_entry.stage.name}"
        if old_entry.evidence.model_dump() != new_entry.evidence.model_dump():
            diff["evidence"] = "counters/workloads updated"
        if len(old_entry.sign_offs) != len(new_entry.sign_offs):
            diff["sign_offs"] = f"{len(old_entry.sign_offs)} -> {len(new_entry.sign_offs)}"
        if diff:
            changes[ac] = diff

    for ac in old_classes:
        if ac not in new.action_classes:
            changes[ac] = {"removed": "no longer in chain"}

    return changes


# Import deferred (module-level forward ref for the type hint).
from remediation.promotion import PromotionFile  # noqa: E402

if __name__ == "__main__":
    main()
