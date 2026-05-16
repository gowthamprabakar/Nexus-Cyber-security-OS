"""`PromotionTracker` — the in-memory + YAML-persisted record of per-action-class state.

The tracker wraps a `PromotionFile` (the Pydantic-validated YAML root). It
exposes:

- `from_path(path)` — load + validate; returns None when the file does not
  exist (safe-by-default per plan Q5/Q7: missing file means every action
  class is Stage 1).
- `empty(cluster_id=...)` — build an in-memory tracker with no action
  classes recorded. Used by the driver when the file is absent but evidence
  still needs to flow into the audit chain.
- `save(path)` — atomic YAML write (tempfile + os.replace). Updates
  `last_modified_at` to now-UTC.
- `stage_for(action_type)` — returns the current stage for one action class,
  defaulting to Stage 1 for untracked ones.
- `record_evidence(action_type, event=..., workload=...)` — increments the
  appropriate evidence counter in-memory. Stage-3-execute events also add
  the workload to the distinct-workloads set; unexpected-rollback events
  reset the consecutive-execute counter to zero.
- `propose_promotions()` — yields the action classes whose accumulated
  evidence meets the criteria for the next stage. Does NOT apply the
  transition — the operator owns that via Task 7's `remediation promotion
  advance` CLI (which uses Pydantic's `PromotionSignOff` model directly).

Promotion criteria encoded here (mirror safety-verification §2):

| Transition       | Criterion (codified in `_propose_for`)                        |
| ---------------- | ------------------------------------------------------------- |
| Stage 1 → 2      | ≥1 stage1_artifact emitted (operator confirmation separate). |
| Stage 2 → 3      | ≥5 stage2_dry_runs.                                          |
| Stage 3 → 4      | ≥30 consecutive Stage-3 successes AND ≥10 distinct workloads. |

The Stage 3 → 4 proposal is informational only — Task 8's CLI refuses the
actual advance until the rolled-back-path xfail lands and ≥4 weeks of
customer Stage-3 evidence accumulates (plan Q8 + safety-verification §6).

The companion `PromotionGateError` is raised by the driver's pre-flight
gate (Task 5) when a finding's action class hasn't earned the requested
mode; the CLI surfaces it as `click.UsageError` (Task 7).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import yaml

from remediation.promotion.events import (
    ACTION_PROMOTION_EVIDENCE_STAGE1,
    ACTION_PROMOTION_EVIDENCE_STAGE2,
    ACTION_PROMOTION_EVIDENCE_STAGE3,
    ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
)
from remediation.promotion.schemas import (
    ActionClassPromotion,
    PromotionFile,
    PromotionStage,
)
from remediation.schemas import RemediationActionType

# ---------------------------- promotion thresholds ----------------------

_STAGE1_ARTIFACT_THRESHOLD: Final[int] = 1
"""Number of artifacts that must have been emitted before the tracker
proposes Stage 1 → 2. The operator-side confirmation ("I hand-applied at
least one and it worked") is verified out-of-band; the threshold here is
just "the agent has produced something to confirm."""

_STAGE2_DRY_RUN_THRESHOLD: Final[int] = 5
"""Successful dry-runs required for Stage 2 → 3. Safety-verification §2."""

_STAGE3_CONSECUTIVE_THRESHOLD: Final[int] = 30
"""Consecutive Stage-3 successes (since last unexpected rollback) required
for Stage 3 → 4. Safety-verification §2."""

_STAGE3_DISTINCT_WORKLOAD_THRESHOLD: Final[int] = 10
"""Distinct workloads (namespace/workload pairs) the action class must have
operated on for Stage 3 → 4. Safety-verification §2."""

_EVIDENCE_EVENTS: Final[frozenset[str]] = frozenset(
    {
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
    }
)
"""The 4 evidence events `record_evidence` accepts. Transition events
(advance/demote/init/reconcile/proposed) are rejected — they belong to
operator-facing CLI methods, not the evidence-accumulation surface."""


class PromotionGateError(RuntimeError):
    """Raised when a finding's action class hasn't earned the requested mode.

    The message must name the action class, the current stage, the requested
    mode, and the remedy (lower the mode or promote the action class via
    `remediation promotion advance`). Surfaces from the CLI as
    `click.UsageError`; library callers see the typed exception.
    """


@dataclass(frozen=True)
class PromotionProposal:
    """The tracker's proposal that an action class be advanced to the next stage.

    Returned by `propose_promotions()`. Informational only — applying the
    proposal is the operator's job (via the CLI `advance` subcommand in
    Task 7), and Task 8 may refuse the application if a global gate (e.g.
    Stage-3 → Stage-4 rolled-back-path prerequisite) hasn't cleared.
    """

    action_type: RemediationActionType
    from_stage: PromotionStage
    to_stage: PromotionStage
    reason: str
    evidence_summary: dict[str, int]


class PromotionTracker:
    """Per-cluster promotion-state tracker."""

    def __init__(self, file: PromotionFile) -> None:
        self._file = file

    @property
    def file(self) -> PromotionFile:
        """Read-only view of the current state. Callers read `tracker.file`
        but mutate via the tracker's methods (so invariants hold)."""
        return self._file

    # ---------------------------- loaders --------------------------------

    @classmethod
    def from_path(cls, path: Path | str) -> PromotionTracker | None:
        """Load a tracker from a YAML file.

        Returns `None` when the file does not exist — the safe-by-default
        semantic (every action class is implicitly at Stage 1). The driver
        (Task 5) interprets `None` accordingly and proceeds with
        recommend-only operations.

        Raises:
            pydantic.ValidationError: file exists but its contents do not
                satisfy `PromotionFile`'s schema invariants. Operators see
                the error and either fix the file by hand or run
                `remediation promotion reconcile` to rebuild from the chain.
        """
        p = Path(path)
        if not p.exists():
            return None
        raw = p.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        return cls(PromotionFile.model_validate(data))

    @classmethod
    def empty(cls, *, cluster_id: str = "default") -> PromotionTracker:
        """Construct an in-memory tracker with no action classes recorded.

        Used by the driver when promotion.yaml is absent but evidence still
        needs to accumulate (for audit-chain replay later). Operators can
        promote `cluster_id` via the CLI when initialising a real file.
        """
        now = datetime.now(UTC)
        return cls(
            PromotionFile(
                cluster_id=cluster_id,
                created_at=now,
                last_modified_at=now,
            )
        )

    # ---------------------------- savers ---------------------------------

    def save(self, path: Path | str) -> None:
        """Atomically write the tracker's state to `path`.

        Updates `last_modified_at` to `datetime.now(UTC)`. Writes to a
        sibling tempfile then `os.replace` to the target — a process killed
        mid-write cannot leave a partially-written `promotion.yaml`.

        Creates the parent directory if it does not exist (mirrors the
        atomic-write conventions used by `audit.AuditLog`).
        """
        p = Path(path)
        self._file.last_modified_at = datetime.now(UTC)
        payload = self._file.model_dump(mode="json")

        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path_str = tempfile.mkstemp(
            prefix=p.name + ".",
            suffix=".tmp",
            dir=str(p.parent),
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                yaml.safe_dump(payload, fh, sort_keys=False, default_flow_style=False)
            os.replace(tmp_path, p)
        except Exception:
            # Don't leave a stale tempfile lying around if the save failed.
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    # ---------------------------- query ----------------------------------

    def stage_for(self, action_type: RemediationActionType) -> PromotionStage:
        """Return the current stage for `action_type`.

        Defaults to `PromotionStage.STAGE_1` for action types not tracked
        in the underlying file — the safe-by-default semantic the pre-flight
        gate relies on.
        """
        entry = self._file.action_classes.get(action_type.value)
        if entry is None:
            return PromotionStage.STAGE_1
        return entry.stage

    # ---------------------------- mutators -------------------------------

    def record_evidence(
        self,
        action_type: RemediationActionType,
        *,
        event: str,
        workload: str | None = None,
    ) -> None:
        """Increment the appropriate evidence counter in-memory.

        Args:
            action_type: the remediation action class the evidence is for.
            event: one of the 4 evidence-event string constants from
                `remediation.promotion.events`. Unknown events raise
                `ValueError`; transition events (advance / demote / init /
                proposed / reconcile) are deliberately rejected — those
                belong to operator-facing CLI flows.
            workload: required for `ACTION_PROMOTION_EVIDENCE_STAGE3` (the
                successful-execute event); identifies the
                "namespace/workload_name" the action acted on. Used to grow
                `stage3_distinct_workloads` toward the Stage-3 → Stage-4
                ≥10-workloads threshold. Ignored for other events.

        Side effects:
            - stage1: +1 stage1_artifacts.
            - stage2: +1 stage2_dry_runs.
            - stage3: +1 stage3_executes, +1 stage3_consecutive_executes,
              workload added to stage3_distinct_workloads.
            - unexpected_rollback: +1 stage3_unexpected_rollbacks, AND
              stage3_consecutive_executes resets to 0 (a rolled-back action
              breaks the consecutive run).

        Creates an empty ActionClassPromotion entry at Stage 1 if the
        action class is not yet tracked — newly-encountered action classes
        start accumulating evidence as soon as the first operation fires.
        """
        if event not in _EVIDENCE_EVENTS:
            raise ValueError(
                f"unknown evidence event {event!r}; expected one of "
                f"{sorted(_EVIDENCE_EVENTS)} "
                f"(transition events advance/demote/init/proposed/reconcile "
                f"are not accepted by record_evidence — use the operator CLI)"
            )

        entry = self._get_or_create(action_type)
        evidence = entry.evidence

        if event == ACTION_PROMOTION_EVIDENCE_STAGE1:
            evidence.stage1_artifacts = evidence.stage1_artifacts + 1
        elif event == ACTION_PROMOTION_EVIDENCE_STAGE2:
            evidence.stage2_dry_runs = evidence.stage2_dry_runs + 1
        elif event == ACTION_PROMOTION_EVIDENCE_STAGE3:
            if workload is None or not workload.strip():
                raise ValueError(
                    f"workload is required for {event!r} events "
                    f"(used to populate stage3_distinct_workloads)"
                )
            # Pydantic's validate_assignment re-runs the cross-field
            # invariants on every assignment — increment total + consecutive
            # together so the bounds invariants stay satisfied step-by-step.
            new_total = evidence.stage3_executes + 1
            new_consecutive = evidence.stage3_consecutive_executes + 1
            evidence.stage3_executes = new_total
            evidence.stage3_consecutive_executes = new_consecutive
            evidence.stage3_distinct_workloads = sorted(
                set(evidence.stage3_distinct_workloads) | {workload}
            )
        else:  # ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK
            # Reset consecutive FIRST so the (consecutive ≤ total) invariant
            # holds when we then bump total.
            evidence.stage3_consecutive_executes = 0
            evidence.stage3_unexpected_rollbacks = evidence.stage3_unexpected_rollbacks + 1

    # ---------------------------- proposal -------------------------------

    def propose_promotions(self) -> list[PromotionProposal]:
        """Yield `PromotionProposal`s for action classes whose accumulated
        evidence meets the criterion for advancing one stage.

        Proposals are informational — the operator owns the actual advance
        via the CLI. Task 8 may additionally refuse the apply (e.g. Stage 3
        → 4 is globally gated until the rolled-back-path xfail lands), but
        that's outside the tracker's responsibility.

        Returns proposals in the order the action classes appear in the
        underlying file (Pydantic preserves dict insertion order).
        """
        proposals: list[PromotionProposal] = []
        for entry in self._file.action_classes.values():
            proposal = self._propose_for(entry)
            if proposal is not None:
                proposals.append(proposal)
        return proposals

    # ---------------------------- internals ------------------------------

    def _get_or_create(
        self,
        action_type: RemediationActionType,
    ) -> ActionClassPromotion:
        """Return the existing entry for `action_type` or insert a fresh
        Stage-1 entry and return it."""
        key = action_type.value
        existing = self._file.action_classes.get(key)
        if existing is not None:
            return existing
        new_entry = ActionClassPromotion(action_type=action_type)
        self._file.action_classes[key] = new_entry
        return new_entry

    def _propose_for(
        self,
        entry: ActionClassPromotion,
    ) -> PromotionProposal | None:
        """Compute the next-stage proposal for one action class, if any."""
        evidence = entry.evidence
        if entry.stage == PromotionStage.STAGE_1:
            if evidence.stage1_artifacts >= _STAGE1_ARTIFACT_THRESHOLD:
                return PromotionProposal(
                    action_type=entry.action_type,
                    from_stage=PromotionStage.STAGE_1,
                    to_stage=PromotionStage.STAGE_2,
                    reason=(
                        f"agent has emitted {evidence.stage1_artifacts} "
                        f"artifact(s); operator confirms ≥1 worked when "
                        f"hand-applied to complete the Stage 1 → 2 evidence."
                    ),
                    evidence_summary={"stage1_artifacts": evidence.stage1_artifacts},
                )
            return None
        if entry.stage == PromotionStage.STAGE_2:
            if evidence.stage2_dry_runs >= _STAGE2_DRY_RUN_THRESHOLD:
                return PromotionProposal(
                    action_type=entry.action_type,
                    from_stage=PromotionStage.STAGE_2,
                    to_stage=PromotionStage.STAGE_3,
                    reason=(
                        f"{evidence.stage2_dry_runs} successful dry-runs "
                        f"(threshold ≥{_STAGE2_DRY_RUN_THRESHOLD})."
                    ),
                    evidence_summary={"stage2_dry_runs": evidence.stage2_dry_runs},
                )
            return None
        if entry.stage == PromotionStage.STAGE_3:
            distinct = len(evidence.stage3_distinct_workloads)
            consecutive = evidence.stage3_consecutive_executes
            if (
                consecutive >= _STAGE3_CONSECUTIVE_THRESHOLD
                and distinct >= _STAGE3_DISTINCT_WORKLOAD_THRESHOLD
            ):
                return PromotionProposal(
                    action_type=entry.action_type,
                    from_stage=PromotionStage.STAGE_3,
                    to_stage=PromotionStage.STAGE_4,
                    reason=(
                        f"{consecutive} consecutive Stage-3 successes "
                        f"(threshold ≥{_STAGE3_CONSECUTIVE_THRESHOLD}) "
                        f"across {distinct} distinct workloads "
                        f"(threshold ≥{_STAGE3_DISTINCT_WORKLOAD_THRESHOLD}). "
                        f"**Security-lead sign-off + Stage-4 global gate "
                        f"(rolled-back-path webhook fixture + ≥4 weeks "
                        f"customer Stage-3 evidence) required at apply time.**"
                    ),
                    evidence_summary={
                        "stage3_consecutive_executes": consecutive,
                        "stage3_distinct_workloads": distinct,
                        "stage3_unexpected_rollbacks": evidence.stage3_unexpected_rollbacks,
                    },
                )
            return None
        # Stage 4 is the top; no further proposals.
        return None


__all__ = ["PromotionGateError", "PromotionProposal", "PromotionTracker"]
