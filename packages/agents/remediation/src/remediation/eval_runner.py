"""`RemediationEvalRunner` — canonical `EvalRunner` for A.1.

Mirrors D.6's
[`eval_runner.py`](../../../k8s-posture/src/k8s_posture/eval_runner.py) shape —
parses the YAML fixture, monkey-patches the agent's three side-effect surfaces
(filesystem ingest, kubectl executor, validator's D.6 detector closure), builds
an `ExecutionContract` rooted at the suite-supplied workspace, calls
`remediation.agent.run`, then compares the resulting `RemediationReport` to
`case.expected`.

**Fixture keys** (under `fixture`):

- `mode: str` — `recommend` (default) / `dry_run` / `execute`.
- `authorization: dict` — fields of `Authorization` (mode flags, allowlist,
  blast cap, rollback window). Missing keys fall back to the model defaults.
- `promotion: dict` — v0.1.1 per-action-class promotion state (the same shape
  as `promotion.yaml`). Parsed into a `PromotionFile` and wrapped in a
  `PromotionTracker`, passed through to `agent.run(promotion=...)` so the
  pre-flight stage gate is ACTIVE. When omitted, the runner synthesises a
  permissive tracker (every action class implicitly at Stage 4) so the run
  proceeds without the gate firing — this preserves the safe default for
  legacy cases written before the v0.1.1 schema landed. **All 15 v0.1 +
  v0.1.1 cases declare this field explicitly.**
- `findings: list[dict]` — D.6 `ManifestFinding` records (the input shape A.1
  ingests).
- `dry_run_result: dict` — scripted `kubectl --dry-run=server` result
  (`exit_code` required; `stdout`, `stderr` optional). Used in `dry_run` and
  `execute` modes. Omit for "always succeeds" default.
- `execute_result: dict` — scripted `kubectl patch` result (execute mode only).
- `rollback_result: dict` — scripted inverse-patch result (execute mode only).
- `post_validate_findings: list[dict]` — what the validator's detector returns
  AFTER the rollback window. Empty (or omitted) = patch worked.
- `kubeconfig: str` / `in_cluster: bool` — passed through to `run()`.

**Comparison shape** (under `expected`):

- `finding_count: int` — `report.total`.
- `by_outcome: {outcome_name: int}` — `report.count_by_outcome()`. Checked only
  for the keys you name; other outcomes default to 0.
- `action_types_distinct: int` — number of unique `action_type` values across
  emitted findings. Useful for the mixed-action-class case.
- `by_promotion_proposal: {action_type: {from_stage: int, to_stage: int}}` —
  v0.1.1: assertions against `tracker.propose_promotions()` AFTER the run.
  Used by case 014 (advance-proposed surface).
- `reconcile_matches: bool` — v0.1.1: when `True`, the runner replays the
  run's `audit.jsonl` through `promotion.replay()` and asserts the resulting
  `PromotionFile.action_classes` equals the tracker's live state. The §3
  source-of-truth invariant. Used by case 015 (chain-replay parity).
- `raises: str` — exception class name (e.g. `"AuthorizationError"`). Inverts
  the success check: pass iff the call raises an exception of that type.

Registered via `pyproject.toml`'s `[project.entry-points."nexus_eval_runners"]`
so `eval-framework run --runner remediation` resolves it.
"""

from __future__ import annotations

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.audit import AuditEntry
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from k8s_posture.schemas import Severity
from k8s_posture.tools.manifests import ManifestFinding

from remediation import agent as agent_mod
from remediation import validator as validator_mod
from remediation.authz import Authorization, AuthorizationError
from remediation.promotion import (
    ActionClassPromotion,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    PromotionTracker,
    replay,
)
from remediation.schemas import (
    RemediationActionType,
    RemediationMode,
    RemediationReport,
)
from remediation.tools import kubectl_executor as kc_mod
from remediation.tools.kubectl_executor import PatchResult


class RemediationEvalRunner:
    """Reference `EvalRunner` for the Remediation Agent."""

    @property
    def agent_name(self) -> str:
        return "remediation"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)

        expected_raises = case.expected.get("raises")
        # Construct the tracker BEFORE run() so we can call propose_promotions()
        # and replay() against it after the run completes. The tracker is
        # mutated in-place by `agent.run` (evidence accumulation), so its
        # post-run state is the live state used for v0.1.1 assertions.
        tracker = _build_tracker(case)
        try:
            report = await _run_case_async(
                case, contract, llm_provider=llm_provider, tracker=tracker
            )
        except AuthorizationError as exc:
            if expected_raises == "AuthorizationError":
                audit_log_path = Path(contract.workspace) / "audit.jsonl"
                return (
                    True,
                    None,
                    {"raised": "AuthorizationError", "message": str(exc)},
                    audit_log_path if audit_log_path.exists() else None,
                )
            return (
                False,
                f"unexpected AuthorizationError: {exc}",
                {"raised": "AuthorizationError", "message": str(exc)},
                None,
            )

        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        if expected_raises:
            return (
                False,
                f"expected {expected_raises} to be raised; run completed normally",
                _actuals(report, tracker=tracker, audit_log_path=audit_log_path),
                audit_log_path,
            )

        passed, failure_reason = _evaluate(
            case, report, tracker=tracker, audit_log_path=audit_log_path
        )
        return (
            passed,
            failure_reason,
            _actuals(report, tracker=tracker, audit_log_path=audit_log_path),
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
    tracker: PromotionTracker,
) -> RemediationReport:
    fixture = case.fixture
    mode = _parse_mode(fixture.get("mode", "recommend"))
    auth = _parse_authorization(fixture.get("authorization") or {})
    findings = tuple(_parse_manifest(r) for r in fixture.get("findings", []) or [])
    dry_run_result = _parse_patch_result(fixture.get("dry_run_result"), default_dry_run=True)
    execute_result = _parse_patch_result(fixture.get("execute_result"), default_dry_run=False)
    rollback_result = _parse_patch_result(fixture.get("rollback_result"), default_dry_run=False)
    post_validate = tuple(
        _parse_manifest(r) for r in fixture.get("post_validate_findings", []) or []
    )

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    findings_path = workspace / "_fixture_findings.json"
    findings_path.write_text("placeholder")

    async def fake_read(*, path: Path | str) -> tuple[ManifestFinding, ...]:
        del path
        return findings

    async def _apply(artifact: Any, *, dry_run: bool, **_: Any) -> PatchResult:
        if dry_run:
            return dry_run_result
        # The validator's rollback() builds an inverse artifact with
        # correlation_id="<orig>-rollback"; key off that to route results.
        if artifact.correlation_id.endswith("-rollback"):
            return rollback_result
        return execute_result

    async def fake_detect() -> tuple[ManifestFinding, ...]:
        return post_validate

    def fake_factory(*, namespace: str, kubeconfig: Path | None, in_cluster: bool) -> Any:
        del namespace, kubeconfig, in_cluster
        return fake_detect

    async def _instant(_seconds: float) -> None:
        return None

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_findings", fake_read))
        stack.enter_context(patch.object(agent_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(validator_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(kc_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(agent_mod, "build_d6_detector", fake_factory))
        # Bypass the validator's rollback-window wait. `patch.object` on
        # `validator_mod.asyncio` would require `asyncio` to be in
        # `validator.__all__` (mypy-strict), so target the attribute path via
        # string-form `patch()` instead.
        stack.enter_context(patch("remediation.validator.asyncio.sleep", _instant))
        # Stub the binary check so absence of kubectl doesn't fail eval-time.
        stack.enter_context(
            patch.object(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
        )
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            findings_path=findings_path,
            mode=mode,
            authorization=auth,
            promotion=tracker,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_eval",
        task=case.description or case.case_id,
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
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


def _evaluate(
    case: EvalCase,
    report: RemediationReport,
    *,
    tracker: PromotionTracker,
    audit_log_path: Path,
) -> tuple[bool, str | None]:
    expected = case.expected

    finding_count = expected.get("finding_count")
    if finding_count is not None and report.total != int(finding_count):
        return False, f"finding_count expected {finding_count}, got {report.total}"

    by_outcome = expected.get("by_outcome") or {}
    counts = report.count_by_outcome()
    for outcome_name, want in by_outcome.items():
        actual = counts.get(str(outcome_name), 0)
        if actual != int(want):
            return False, (
                f"by_outcome[{outcome_name!r}] expected {want}, got {actual} "
                f"(full counts: {counts})"
            )

    distinct = expected.get("action_types_distinct")
    if distinct is not None:
        seen = _distinct_action_types(report)
        if len(seen) != int(distinct):
            return False, (
                f"action_types_distinct expected {distinct}, got {len(seen)} ({sorted(seen)})"
            )

    by_proposal = expected.get("by_promotion_proposal")
    if by_proposal is not None:
        actual_proposals = _propose_summary(tracker)
        for action_type_str, want in dict(by_proposal).items():
            got = actual_proposals.get(str(action_type_str))
            if got is None:
                return False, (
                    f"by_promotion_proposal[{action_type_str!r}] expected "
                    f"{dict(want)}, got no proposal (proposals: {actual_proposals})"
                )
            want_from = int(dict(want)["from_stage"])
            want_to = int(dict(want)["to_stage"])
            if got["from_stage"] != want_from or got["to_stage"] != want_to:
                return False, (
                    f"by_promotion_proposal[{action_type_str!r}] expected "
                    f"from_stage={want_from} to_stage={want_to}, got {got}"
                )

    reconcile_matches_expected = expected.get("reconcile_matches")
    if reconcile_matches_expected is not None:
        matches = _reconcile_matches(tracker=tracker, audit_log_path=audit_log_path)
        if matches != bool(reconcile_matches_expected):
            return False, (
                f"reconcile_matches expected {bool(reconcile_matches_expected)}, got {matches} "
                f"(replay(audit chain) != tracker state — the §3 source-of-truth invariant)"
            )

    return True, None


def _actuals(
    report: RemediationReport,
    *,
    tracker: PromotionTracker,
    audit_log_path: Path,
) -> dict[str, Any]:
    return {
        "finding_count": report.total,
        "by_outcome": report.count_by_outcome(),
        "action_types_distinct": len(_distinct_action_types(report)),
        "by_promotion_proposal": _propose_summary(tracker),
        "reconcile_matches": _reconcile_matches(tracker=tracker, audit_log_path=audit_log_path),
    }


def _propose_summary(tracker: PromotionTracker) -> dict[str, dict[str, int]]:
    """Compute `tracker.propose_promotions()` and serialise to the YAML shape.

    Returns a dict keyed by `action_type.value` with `{from_stage, to_stage}`
    inner dicts — matches the `expected.by_promotion_proposal` shape that
    case 014 asserts.
    """
    return {
        proposal.action_type.value: {
            "from_stage": int(proposal.from_stage),
            "to_stage": int(proposal.to_stage),
        }
        for proposal in tracker.propose_promotions()
    }


def _reconcile_matches(*, tracker: PromotionTracker, audit_log_path: Path) -> bool:
    """Replay the run's audit chain and compare to the live tracker state.

    The §3 source-of-truth invariant: `promotion.yaml` (the tracker's in-memory
    state) is the cache; the F.6 hash-chained audit log is the source of truth.
    For any consistent run, `replay(chain) == tracker.file` (modulo
    `cluster_id`, `created_at`, and `last_modified_at`, which are clock-bound).

    Returns True when the per-action-class state (stage + evidence counters +
    sign-offs) matches.
    """
    if not audit_log_path.exists():
        # Empty chain replays to an empty file; only matches if the tracker
        # is also empty.
        return not tracker.file.action_classes
    entries = _read_audit_entries(audit_log_path)
    replayed = replay(entries, default_cluster_id=tracker.file.cluster_id)
    live_classes = {
        k: v.model_dump(mode="json", exclude={"updated_at"})
        for k, v in tracker.file.action_classes.items()
    }
    replayed_classes = {
        k: v.model_dump(mode="json", exclude={"updated_at"})
        for k, v in replayed.action_classes.items()
    }
    return live_classes == replayed_classes


def _read_audit_entries(path: Path) -> list[AuditEntry]:
    """Read the run's `audit.jsonl` line-by-line into `AuditEntry` objects.

    Mirrors the CLI reconcile path
    ([`cli.py`](cli.py)'s `promotion_reconcile_cmd`) — JSONL on disk, one
    entry per line, parsed via `AuditEntry.from_json`. `replay()` then walks
    the list and ignores non-`promotion.*` entries silently.
    """
    return [
        AuditEntry.from_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _distinct_action_types(report: RemediationReport) -> set[str]:
    """Pull `action_type` out of each OCSF 2007 finding (under `finding_info.types[0]`)."""
    seen: set[str] = set()
    for raw in report.findings:
        try:
            types = raw["finding_info"]["types"]
        except (KeyError, TypeError):
            continue
        if isinstance(types, list) and types and isinstance(types[0], str):
            seen.add(types[0])
    return seen


# ---------------------------- fixture -> promotion tracker --------------


def _build_tracker(case: EvalCase) -> PromotionTracker:
    """Construct the `PromotionTracker` the agent will use for this case.

    When `fixture.promotion` is present, parse it directly into a
    `PromotionFile` (Pydantic does the validation — schema_version pin,
    stage-matches-latest-signoff invariant, etc.) and wrap in a
    `PromotionTracker`. Action classes not listed in `action_classes` are
    implicitly at Stage 1 (the floor); the tracker's `stage_for(...)` method
    returns Stage 1 for absent keys, matching the safe-by-default semantic.

    When `fixture.promotion` is absent, the runner synthesises a permissive
    tracker — every action class is implicitly at Stage 4. This is the
    "default when omitted" reserved in the eval/README.md schema: legacy
    fixtures without the promotion field run with the gate effectively
    disabled, preserving their original outcomes. v0.1.1 cases declare the
    field explicitly so the gate is exercised.

    Note: PromotionStage.STAGE_4 is the per-class maximum the tracker can
    carry; the **global Stage-4 closure** (the rolled-back-path webhook
    fixture + ≥4 weeks customer Stage-3 evidence) is enforced by the CLI's
    `advance` / `reconcile` Stage-4 gate, NOT by `stage_for()`. Synthesising
    Stage 4 here is therefore safe — the eval runner is not the gate.
    """
    promotion_dict = case.fixture.get("promotion")
    if isinstance(promotion_dict, dict):
        return PromotionTracker(PromotionFile.model_validate(promotion_dict))
    return _synth_permissive_tracker(case)


def _synth_permissive_tracker(case: EvalCase) -> PromotionTracker:
    """Build a Stage-4-everywhere tracker for legacy fixtures.

    Iterates the case's findings, maps each `rule_id` to its action class via
    the registry, and seeds the tracker with `action_classes` entries at
    Stage 4 (with the minimal two-advance sign-off chain Pydantic requires).
    """
    findings = case.fixture.get("findings", []) or []
    now = datetime.now(UTC)
    file = PromotionFile(cluster_id="eval-permissive", created_at=now, last_modified_at=now)
    seen: set[str] = set()
    for raw in findings:
        rule_id = str((raw or {}).get("rule_id", ""))
        action_type = _action_type_for_rule(rule_id)
        if action_type is None or action_type.value in seen:
            continue
        seen.add(action_type.value)
        file.action_classes[action_type.value] = ActionClassPromotion(
            action_type=action_type,
            stage=PromotionStage.STAGE_4,
            sign_offs=_full_signoff_chain(now),
        )
    return PromotionTracker(file)


def _action_type_for_rule(rule_id: str) -> RemediationActionType | None:
    """Map a D.6 `rule_id` to its v0.1 `RemediationActionType`.

    Mirrors `action_classes.registry.build_registry`'s mapping (the same
    mapping the agent uses); kept inline here to keep the eval-runner's
    dependency surface small.
    """
    mapping = {
        "run-as-root": RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        "missing-resource-limits": RemediationActionType.K8S_PATCH_RESOURCE_LIMITS,
        "image-pull-policy-not-always": RemediationActionType.K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS,
        "read-only-root-filesystem": RemediationActionType.K8S_PATCH_READ_ONLY_ROOT_FS,
        "allow-privilege-escalation": (
            RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION
        ),
    }
    return mapping.get(rule_id)


def _full_signoff_chain(now: datetime) -> list[PromotionSignOff]:
    """Build a [advance(1->2), advance(2->3), advance(3->4)] sign-off chain.

    Required by Pydantic's "stage matches latest sign-off" invariant on
    ActionClassPromotion when stage > 1. Used only by the permissive synth
    path — real cases declare their own sign-offs.
    """
    return [
        PromotionSignOff(
            event_kind="advance",
            operator="eval-permissive-synth",
            timestamp=now,
            reason="permissive tracker — legacy fixture without explicit promotion declaration",
            from_stage=PromotionStage.STAGE_1,
            to_stage=PromotionStage.STAGE_2,
        ),
        PromotionSignOff(
            event_kind="advance",
            operator="eval-permissive-synth",
            timestamp=now,
            reason="permissive tracker — legacy fixture without explicit promotion declaration",
            from_stage=PromotionStage.STAGE_2,
            to_stage=PromotionStage.STAGE_3,
        ),
        PromotionSignOff(
            event_kind="advance",
            operator="eval-permissive-synth",
            timestamp=now,
            reason="permissive tracker — legacy fixture without explicit promotion declaration",
            from_stage=PromotionStage.STAGE_3,
            to_stage=PromotionStage.STAGE_4,
        ),
    ]


# ---------------------------- fixture -> dataclass parsing ---------------


def _parse_mode(value: Any) -> RemediationMode:
    if isinstance(value, RemediationMode):
        return value
    return RemediationMode(str(value).lower())


def _parse_authorization(raw: dict[str, Any]) -> Authorization:
    return Authorization.model_validate(raw)


def _parse_patch_result(raw: Any, *, default_dry_run: bool) -> PatchResult:
    """Build a PatchResult from a fixture dict.

    Defaults to "succeeded" so the simple-success cases don't need to spell out
    `exit_code: 0` repeatedly. Pre/post hashes are stubbed deterministically
    for execute results so the audit chain stays uniform.
    """
    raw = raw or {}
    exit_code = int(raw.get("exit_code", 0))
    succeeded = exit_code == 0
    dry_run_flag = bool(raw.get("dry_run", default_dry_run))
    return PatchResult(
        exit_code=exit_code,
        stdout=str(raw.get("stdout", "deployment.apps/test patched" if succeeded else "")),
        stderr=str(raw.get("stderr", "" if succeeded else "kubectl: error")),
        dry_run=dry_run_flag,
        pre_patch_hash=("a" * 64) if (succeeded and not dry_run_flag) else None,
        post_patch_hash=("b" * 64) if (succeeded and not dry_run_flag) else None,
        pre_patch_resource={"kind": "Deployment"} if (succeeded and not dry_run_flag) else None,
        post_patch_resource=(
            {"kind": "Deployment", "patched": True} if (succeeded and not dry_run_flag) else None
        ),
    )


def _parse_manifest(raw: dict[str, Any]) -> ManifestFinding:
    return ManifestFinding(
        rule_id=str(raw.get("rule_id", "")),
        rule_title=str(raw.get("rule_title", "")),
        severity=_parse_severity(raw.get("severity", "high")),
        workload_kind=str(raw.get("workload_kind", "")),
        workload_name=str(raw.get("workload_name", "")),
        namespace=str(raw.get("namespace", "default")),
        container_name=str(raw.get("container_name", "")),
        manifest_path=str(raw.get("manifest_path", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    return Severity(str(value).lower())


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


# Reserved for the v0.2+ expanded action-class set; the test suite asserts
# the registry is still in sync.
_KNOWN_ACTION_TYPES: set[str] = {t.value for t in RemediationActionType}


__all__ = ["RemediationEvalRunner"]
