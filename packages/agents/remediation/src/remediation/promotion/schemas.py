"""Promotion-state schemas — Pydantic models for the per-action-class graduation pipeline.

Six public types form the contract every later task (3-8) operates on:

- `PromotionStage` — IntEnum (1-4) of graduation stages.
- `stage_max_mode(stage) -> RemediationMode` — the maximum-permitted operational
  mode for an action class at this stage. The pre-flight gate (Task 5) enforces
  this mapping per finding.
- `PromotionEvidence` — counters tracking accumulated evidence per action class.
- `PromotionSignOff` — one operator-applied stage transition event.
- `ActionClassPromotion` — one action class's full state (stage + evidence +
  sign-off history) in one customer environment.
- `PromotionFile` — the YAML root: schema version + cluster id + per-action map.

Validation invariants enforced at the schema level:

- All counters are non-negative.
- `stage3_unexpected_rollbacks` ≤ `stage3_executes` (you cannot have more
  unexpected rollbacks than executions; the agent emits exactly one of the
  two per Stage-3 outcome).
- `stage3_consecutive_executes` ≤ `stage3_executes` (consecutive run length
  cannot exceed total count).
- Sign-offs must be chronologically ordered (timestamps non-decreasing).
- An `advance` sign-off must move stage by exactly +1.
- A `demote` sign-off must move to a strictly lower stage.
- `schema_version` is a literal `"0.1"` — bumping the schema is a deliberate
  act tracked as a separate migration.
- `action_classes` keys must match a registered `RemediationActionType`.

The "is this evidence sufficient for the next stage?" logic lives in the
tracker (Task 3) — schemas only validate well-formedness here.

See [safety-verification §2](../../../../../../docs/_meta/a1-safety-verification-2026-05-16.md#2-the-four-stage-earned-autonomy-pipeline)
for the four-stage promotion-criteria definitions this schema supports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from remediation.schemas import RemediationActionType, RemediationMode

PROMOTION_FILE_SCHEMA_VERSION: Literal["0.1"] = "0.1"
"""Schema version pinned in every `PromotionFile`. Forces explicit migration
when the field set grows (Task 2 ships v0.1; v0.2+ would land with a separate
migration plan)."""


# ---------------------------- stage enum ---------------------------------


class PromotionStage(IntEnum):
    """Graduation stage for an action class within one customer environment.

    Ordered so `PromotionStage.STAGE_2 > PromotionStage.STAGE_1` is true —
    enables straightforward "at least Stage N?" checks. IntEnum (not Enum)
    so YAML serialization round-trips as integer.
    """

    STAGE_1 = 1
    STAGE_2 = 2
    STAGE_3 = 3
    STAGE_4 = 4


_STAGE_MAX_MODE: dict[PromotionStage, RemediationMode] = {
    PromotionStage.STAGE_1: RemediationMode.RECOMMEND,
    PromotionStage.STAGE_2: RemediationMode.DRY_RUN,
    PromotionStage.STAGE_3: RemediationMode.EXECUTE,
    PromotionStage.STAGE_4: RemediationMode.EXECUTE,
}


def stage_max_mode(stage: PromotionStage) -> RemediationMode:
    """Return the maximum-risk `RemediationMode` permitted at this stage.

    Stage 4's unattended-scheduled distinction is enforced separately (the
    scheduler is a Phase-1c surface task); per-invocation both Stage 3 and
    Stage 4 cap at `RemediationMode.EXECUTE`.
    """
    return _STAGE_MAX_MODE[stage]


# ---------------------------- evidence + sign-off ------------------------


class PromotionEvidence(BaseModel):
    """Per-action-class evidence counters.

    The four Stage-2/3 counters drive automatic promotion proposals (Task 3
    `propose_promotions()`); `stage1_artifacts` is informational only because
    Stage 1 → Stage 2 transitions require operator confirmation that the
    artifact actually worked when hand-applied (not just that A.1 emitted it).

    `stage3_consecutive_executes` is the rolling count since the last
    `unexpected_rollback`; it resets to 0 on every unexpected rollback.
    The Stage 4 promotion criterion requires it ≥ 30. `stage3_distinct_workloads`
    captures the "≥10 distinct workloads" facet of the same criterion.
    """

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    stage1_artifacts: int = Field(default=0, ge=0)
    """Total count of artifacts the agent has generated for this action class.
    Informational; Stage-1 → Stage-2 promotion is operator-confirmed, not
    counter-driven."""

    stage2_dry_runs: int = Field(default=0, ge=0)
    """Successful dry-runs (kubectl --dry-run=server exit 0). Stage-2 → Stage-3
    requires ≥5."""

    stage3_executes: int = Field(default=0, ge=0)
    """Successful Stage-3 executions (executed_validated outcomes; rollbacks
    that fired correctly count separately under unexpected_rollbacks)."""

    stage3_consecutive_executes: int = Field(default=0, ge=0)
    """Run length of consecutive Stage-3 successes since the last unexpected
    rollback. Stage-3 → Stage-4 requires ≥30."""

    stage3_unexpected_rollbacks: int = Field(default=0, ge=0)
    """Stage-3 executions that ended in `executed_rolled_back` without
    attribution to an external mutating webhook. Each one zeroes
    `stage3_consecutive_executes`."""

    stage3_distinct_workloads: list[str] = Field(default_factory=list)
    """De-duplicated, sorted set of `"<namespace>/<workload_name>"` pairs
    on which the action class has been executed (any stage). Stage-3 →
    Stage-4 requires len() ≥ 10."""

    @field_validator("stage3_distinct_workloads")
    @classmethod
    def _dedupe_and_sort_workloads(cls, value: list[str]) -> list[str]:
        """Strip duplicates and sort. Operators editing promotion.yaml by hand
        shouldn't be able to inflate the workload count by repeating entries."""
        return sorted(set(value))

    @model_validator(mode="after")
    def _evidence_invariants(self) -> PromotionEvidence:
        """Cross-field invariants — see module docstring for the rationale."""
        if self.stage3_unexpected_rollbacks > self.stage3_executes:
            raise ValueError(
                f"stage3_unexpected_rollbacks ({self.stage3_unexpected_rollbacks}) > "
                f"stage3_executes ({self.stage3_executes}) — the agent emits exactly "
                f"one of the two per Stage-3 outcome, so the counters are bounded by total executes"
            )
        if self.stage3_consecutive_executes > self.stage3_executes:
            raise ValueError(
                f"stage3_consecutive_executes ({self.stage3_consecutive_executes}) > "
                f"stage3_executes ({self.stage3_executes}) — consecutive count cannot exceed total"
            )
        return self


class PromotionSignOff(BaseModel):
    """One operator-applied promotion or demotion event.

    `advance` transitions move exactly +1 (no skipping). `demote` transitions
    can be any decrease. Both kinds require a free-text reason — the audit
    chain captures the same payload via `promotion.advance.applied` /
    `promotion.demote.applied` events (Task 4).
    """

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    event_kind: Literal["advance", "demote"]
    """Direction of the transition. `advance` is +1 only; `demote` is any
    decrease."""

    operator: str = Field(min_length=1)
    """Identifier of the human who applied this transition. Operator-supplied
    via the CLI flag or env var; A.1 does not auto-detect."""

    timestamp: datetime
    """When the transition was recorded. Must be timezone-aware (UTC
    canonical); naive datetimes are rejected by the validator."""

    reason: str = Field(min_length=1)
    """Free-text justification. Required for both advance and demote events
    so the audit trail is always non-empty."""

    from_stage: PromotionStage
    """Stage the action class was at before this transition."""

    to_stage: PromotionStage
    """Stage the action class is at after this transition."""

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_aware(cls, value: datetime) -> datetime:
        """Naive datetimes lose meaning across timezones. Force UTC awareness."""
        if value.tzinfo is None:
            raise ValueError(
                "PromotionSignOff.timestamp must be timezone-aware (UTC); "
                f"got naive datetime {value!r}"
            )
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _transition_direction(self) -> PromotionSignOff:
        """Validate the transition matches the event kind:

        - advance: to_stage == from_stage + 1 (no skipping; the safety
          record explicitly forbids Stage-2 → Stage-4 transitions).
        - demote: to_stage < from_stage (any decrease).
        - no-ops (from == to) are always invalid.
        """
        if self.from_stage == self.to_stage:
            raise ValueError(
                f"PromotionSignOff is a no-op: from_stage == to_stage == {self.from_stage}"
            )
        if self.event_kind == "advance":
            if self.to_stage.value != self.from_stage.value + 1:
                raise ValueError(
                    f"advance must move exactly +1 stage; "
                    f"got from={self.from_stage} to={self.to_stage}. "
                    f"Skipping Stage 3 is explicitly forbidden by the safety contract."
                )
        else:  # demote
            if self.to_stage >= self.from_stage:
                raise ValueError(
                    f"demote must move to a strictly lower stage; "
                    f"got from={self.from_stage} to={self.to_stage}"
                )
        return self


# ---------------------------- action-class + file roots ------------------


class ActionClassPromotion(BaseModel):
    """The full per-action-class state in one customer environment.

    `stage` is the current effective stage — the pre-flight gate reads this
    field directly. `evidence` accumulates between transitions; `sign_offs`
    is the audit-aligned history of every advance/demote ever applied.
    """

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    action_type: RemediationActionType
    """The remediation action class this record tracks. Constrained to the
    registered enum so typos can't silently bypass the gate."""

    stage: PromotionStage = PromotionStage.STAGE_1
    """Current effective stage. Defaults to Stage 1 (the safe-by-default
    semantic for any newly-tracked action class)."""

    evidence: PromotionEvidence = Field(default_factory=PromotionEvidence)
    """Accumulated evidence. Tracker increments counters here as Stage-N
    audit events fire (Task 4)."""

    sign_offs: list[PromotionSignOff] = Field(default_factory=list)
    """Ordered history of every advance/demote applied to this action class
    in this environment. Most recent at the tail."""

    @model_validator(mode="after")
    def _stage_consistent_with_sign_offs(self) -> ActionClassPromotion:
        """`stage` must match the `to_stage` of the most recent sign-off (or
        Stage 1 if no sign-offs exist — the default).

        Also enforces sign-off chronological ordering — timestamps must be
        non-decreasing. The reconciler (Task 6) reads the audit chain in
        order so this invariant holds by construction; manual edits to
        promotion.yaml that violate it are rejected by the schema.
        """
        if self.sign_offs:
            # Chronological order.
            for prev, curr in zip(self.sign_offs, self.sign_offs[1:], strict=False):
                if curr.timestamp < prev.timestamp:
                    raise ValueError(
                        f"sign_offs must be chronologically ordered; "
                        f"entry at {curr.timestamp.isoformat()} precedes "
                        f"the prior entry at {prev.timestamp.isoformat()}"
                    )
            latest_to = self.sign_offs[-1].to_stage
            if self.stage != latest_to:
                raise ValueError(
                    f"stage ({self.stage}) does not match the most recent "
                    f"sign-off's to_stage ({latest_to}); promotion.yaml is "
                    f"inconsistent — run `remediation promotion reconcile` "
                    f"to rebuild from the audit chain"
                )
        else:
            if self.stage != PromotionStage.STAGE_1:
                raise ValueError(
                    f"stage is {self.stage} but sign_offs is empty; "
                    f"only Stage 1 is permitted without an explicit sign-off"
                )
        return self


class PromotionFile(BaseModel):
    """The root of `promotion.yaml`.

    One file per customer environment (per cluster, per `Q1` of the plan).
    Layered semantics:

    - Missing file (handled by `PromotionTracker.from_path()` returning None) =
      every action class is Stage 1.
    - File present with empty `action_classes` = same as missing file, but
      explicitly opted-in. `remediation promotion init` writes this state.
    - File present with action classes listed = each one's stage is exactly
      what the file says; unlisted action classes still default to Stage 1.

    `cluster_id` is an operator-supplied label (free-text) so audit logs
    and operator dashboards can disambiguate dev / staging / prod files.
    Not used for any logic — just for human-readable tagging.
    """

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    schema_version: Literal["0.1"] = PROMOTION_FILE_SCHEMA_VERSION
    """Pinned in every file. Future schema growth requires a deliberate
    migration; a v0.2 promotion.yaml will not load as v0.1."""

    cluster_id: str = Field(min_length=1)
    """Operator-supplied free-text label (e.g. `"prod-eu-1"`). Used for
    human-readable tagging in audit logs and dashboards."""

    created_at: datetime
    """When `remediation promotion init` first wrote the file. Timezone-aware
    (UTC canonical)."""

    last_modified_at: datetime
    """Updated on every save. Timezone-aware (UTC canonical)."""

    action_classes: dict[str, ActionClassPromotion] = Field(default_factory=dict)
    """Map from `RemediationActionType.value` to its per-class state.

    Keys are the string form of the action_type enum (so YAML stays
    operator-readable). Unknown keys are rejected by the validator;
    unlisted known keys silently default to Stage 1 at lookup time.
    """

    @field_validator("created_at", "last_modified_at")
    @classmethod
    def _timestamps_must_be_aware(cls, value: datetime) -> datetime:
        """Same UTC discipline as PromotionSignOff."""
        if value.tzinfo is None:
            raise ValueError(
                "PromotionFile timestamps must be timezone-aware (UTC); "
                f"got naive datetime {value!r}"
            )
        return value.astimezone(UTC)

    @field_validator("action_classes")
    @classmethod
    def _action_keys_are_registered(
        cls,
        value: dict[str, ActionClassPromotion],
    ) -> dict[str, ActionClassPromotion]:
        """Keys must match registered RemediationActionType values.

        A typo here would silently make the pre-flight gate skip the entry
        (an unlisted action class defaults to Stage 1, which is permissive
        for recommend-only operations). The validator turns the silent
        skip into a loud failure.
        """
        valid = {member.value for member in RemediationActionType}
        for key, entry in value.items():
            if key not in valid:
                raise ValueError(
                    f"action_classes key {key!r} is not a registered "
                    f"RemediationActionType; valid keys: {sorted(valid)}"
                )
            if entry.action_type.value != key:
                raise ValueError(
                    f"action_classes[{key!r}].action_type is "
                    f"{entry.action_type.value!r}; key and action_type must match"
                )
        return value

    @model_validator(mode="after")
    def _modified_after_created(self) -> PromotionFile:
        """`last_modified_at` ≥ `created_at` — a created-after-modified file is
        either clock skew or tampering."""
        if self.last_modified_at < self.created_at:
            raise ValueError(
                f"last_modified_at ({self.last_modified_at.isoformat()}) < "
                f"created_at ({self.created_at.isoformat()}); file is inconsistent"
            )
        return self


__all__ = [
    "PROMOTION_FILE_SCHEMA_VERSION",
    "ActionClassPromotion",
    "PromotionEvidence",
    "PromotionFile",
    "PromotionSignOff",
    "PromotionStage",
    "stage_max_mode",
]
