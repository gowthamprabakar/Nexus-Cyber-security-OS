"""Promotion-state schemas — Pydantic models for the per-action-class graduation pipeline.

Task 1 ships the **import contract**: `PromotionStage` (the 4-value enum) and
the `stage_max_mode` helper that downstream modules (`tracker.py`,
`replay.py`, the pre-flight gate in `agent.run`) depend on. Task 2 lands the
full `PromotionEvidence`, `PromotionSignOff`, `ActionClassPromotion`, and
`PromotionFile` Pydantic models without changing the names exported below.

The stage → mode mapping is the bright line the pre-flight gate enforces:
a finding whose action class is at Stage `s` cannot be operated on at a
RemediationMode whose risk exceeds `stage_max_mode(s)`. See
[safety-verification §2](../../../../../../docs/_meta/a1-safety-verification-2026-05-16.md#2-the-four-stage-earned-autonomy-pipeline)
for the full stage definitions.
"""

from __future__ import annotations

from enum import IntEnum

from remediation.schemas import RemediationMode


class PromotionStage(IntEnum):
    """Graduation stage for an action class within one customer environment.

    Ordered so `PromotionStage.STAGE_2 > PromotionStage.STAGE_1` is true —
    enables straightforward "is the action class at least Stage N?" checks.
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
    """Return the maximum-risk `RemediationMode` permitted for an action class at this stage.

    Stage 4's unattended-scheduled distinction is enforced separately (the
    scheduler is a Phase-1c surface task); at the per-invocation level both
    Stage 3 and Stage 4 cap at `RemediationMode.EXECUTE`.
    """
    return _STAGE_MAX_MODE[stage]


__all__ = ["PromotionStage", "stage_max_mode"]
