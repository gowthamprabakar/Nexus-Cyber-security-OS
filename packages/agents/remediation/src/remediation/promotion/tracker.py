"""`PromotionTracker` — the in-memory + YAML-persisted record of per-action-class state.

Task 1 stubs the public surface so the rest of the package (and the smoke
tests) can import it. Task 3 fills in the load/save/record_evidence/
propose_promotions methods. The class is intentionally not abstract — the
stubs raise `NotImplementedError` so an accidental call from a downstream
module fails fast rather than silently returning None.

The companion `PromotionGateError` exception is defined here (and not in
`schemas.py`) because raising it is conceptually the tracker's job: the
tracker is what knows the current stage and what the requested mode would
require. The pre-flight gate in `agent.run` (Task 5) catches it and the
CLI (Task 7) re-raises as `click.UsageError`.
"""

from __future__ import annotations


class PromotionGateError(RuntimeError):
    """Raised when a finding's action class hasn't earned the requested mode.

    The message must name the action class, the current stage, the requested
    mode, and the remedy (either lower the mode or promote the action class
    via `remediation promotion advance`). Surfaces from the CLI as
    `click.UsageError`; library callers see the typed exception.
    """


class PromotionTracker:
    """Per-cluster promotion-state tracker.

    Stubbed in Task 1. Task 3 lands:

    - `from_path(path) -> PromotionTracker | None` — classmethod loader.
      Returns `None` when the file is missing so the driver can interpret
      that as "every action class is at Stage 1" (the safe-by-default
      semantic at safety-verification §3 / plan §Q5).
    - `save(path)` — round-trips to YAML.
    - `stage_for(action_type) -> PromotionStage` — defaults to Stage 1 for
      unknown action types.
    - `record_evidence(action_type, event)` — increments the appropriate
      counter in the in-memory state.
    - `propose_promotions()` — yields the list of action classes whose
      accumulated evidence meets the criteria for the next stage.
    """


__all__ = ["PromotionGateError", "PromotionTracker"]
