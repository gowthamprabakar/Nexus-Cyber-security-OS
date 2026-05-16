"""Audit-action constants for the 9 `promotion.*` events.

Defining the constants in Task 1 (rather than waiting for Task 4) lets the
smoke tests assert the vocabulary shape without round-tripping through
`PipelineAuditor`. Task 4 wires these into `audit.PipelineAuditor` as
`record_promotion_*` methods.

Vocabulary growth: A.1 v0.1 ships 11 `remediation.*` audit actions; this
plan adds 9 `promotion.*` actions for a total of 20. All 9 below are
namespaced under `promotion.` so downstream consumers (D.7 Investigation,
F.6 dashboards) can subscribe by prefix.
"""

from __future__ import annotations

# ---------------------------- evidence events ----------------------------
# Emitted on every successful operation. The 4 events are the counters
# `PromotionTracker.record_evidence(...)` will increment.

ACTION_PROMOTION_EVIDENCE_STAGE1 = "promotion.evidence.stage1"
"""Stage-1 artifact emitted (recommend mode produced a kubectl-patch JSON)."""

ACTION_PROMOTION_EVIDENCE_STAGE2 = "promotion.evidence.stage2"
"""Dry-run completed successfully (kubectl --dry-run=server exit 0)."""

ACTION_PROMOTION_EVIDENCE_STAGE3 = "promotion.evidence.stage3"
"""Execute completed and validated (Stage 6 said no rollback required)."""

ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK = "promotion.evidence.unexpected_rollback"
"""Stage-3+ execute rolled back without webhook attribution. A signal the
action class isn't ready for the next stage. Distinct from
`promotion.evidence.stage3` so the tracker can reset Stage-3 counters
on the affected action class."""

# ---------------------------- transition events --------------------------
# Emitted by the operator-facing CLI subcommands + the reconciler.

ACTION_PROMOTION_ADVANCE_PROPOSED = "promotion.advance.proposed"
"""Reconciler determined the criteria for a stage promotion are met.
Informational only — does not change the state file."""

ACTION_PROMOTION_ADVANCE_APPLIED = "promotion.advance.applied"
"""Operator ran `remediation promotion advance` and supplied a sign-off
reason. Mutates `promotion.yaml`."""

ACTION_PROMOTION_DEMOTE_APPLIED = "promotion.demote.applied"
"""Operator ran `remediation promotion demote` after a real-world issue.
Mutates `promotion.yaml`. The reason field is required."""

ACTION_PROMOTION_INIT_APPLIED = "promotion.init.applied"
"""Operator ran `remediation promotion init` on a fresh environment.
Writes an empty Stage-1 file (no action classes promoted)."""

ACTION_PROMOTION_RECONCILE_COMPLETED = "promotion.reconcile.completed"
"""Reconciler finished replaying the audit chain. Payload includes the
number of chain entries replayed and the set of state changes (if any)."""


PROMOTION_ACTIONS: frozenset[str] = frozenset(
    {
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        ACTION_PROMOTION_ADVANCE_PROPOSED,
        ACTION_PROMOTION_ADVANCE_APPLIED,
        ACTION_PROMOTION_DEMOTE_APPLIED,
        ACTION_PROMOTION_INIT_APPLIED,
        ACTION_PROMOTION_RECONCILE_COMPLETED,
    }
)
"""The complete vocabulary. Tests assert `len() == 9` and that every entry
starts with `promotion.`. Anything else under `promotion.*` would be a
contract violation."""


__all__ = [
    "ACTION_PROMOTION_ADVANCE_APPLIED",
    "ACTION_PROMOTION_ADVANCE_PROPOSED",
    "ACTION_PROMOTION_DEMOTE_APPLIED",
    "ACTION_PROMOTION_EVIDENCE_STAGE1",
    "ACTION_PROMOTION_EVIDENCE_STAGE2",
    "ACTION_PROMOTION_EVIDENCE_STAGE3",
    "ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK",
    "ACTION_PROMOTION_INIT_APPLIED",
    "ACTION_PROMOTION_RECONCILE_COMPLETED",
    "PROMOTION_ACTIONS",
]
