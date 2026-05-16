"""Earned-autonomy pipeline — per-action-class promotion tracking for A.1.

Closes the §3 gap of
[`docs/_meta/a1-safety-verification-2026-05-16.md`](../../../../../../docs/_meta/a1-safety-verification-2026-05-16.md):
every action class lives in one of four graduation stages
(`recommend` → `dry_run` → human-approved `execute` → unattended `execute`)
per customer environment. The agent counts evidence; the operator applies
promotions; the audit chain is the source of truth.

Public API (stubbed in Task 1; filled in across Tasks 2-8 of the
[earned-autonomy pipeline plan](../../../../../../docs/superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md)):

- `PromotionStage` — Enum (1-4) of graduation stages.
- `PromotionGateError` — raised by `agent.run()` when a finding's action
  class hasn't earned the requested mode.
- `PromotionTracker` — loads/saves `promotion.yaml`; tracks evidence;
  proposes promotions when criteria are met.
- `stage_max_mode(stage) -> RemediationMode` — the mapping the pre-flight
  gate enforces. Stage 1 → recommend; Stage 2 → dry_run; Stage 3+4 →
  execute (with Stage 4 additionally permitting scheduled unattended
  runs once the scheduler ships).
"""

from remediation.promotion.schemas import (
    PROMOTION_FILE_SCHEMA_VERSION,
    ActionClassPromotion,
    PromotionEvidence,
    PromotionFile,
    PromotionSignOff,
    PromotionStage,
    stage_max_mode,
)
from remediation.promotion.tracker import (
    PromotionGateError,
    PromotionProposal,
    PromotionTracker,
)

__all__ = [
    "PROMOTION_FILE_SCHEMA_VERSION",
    "ActionClassPromotion",
    "PromotionEvidence",
    "PromotionFile",
    "PromotionGateError",
    "PromotionProposal",
    "PromotionSignOff",
    "PromotionStage",
    "PromotionTracker",
    "stage_max_mode",
]
