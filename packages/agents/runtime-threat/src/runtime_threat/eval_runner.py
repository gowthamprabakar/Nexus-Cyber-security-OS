"""Stub for `RuntimeThreatEvalRunner` — replaced by D.3 Task 13.

The stub exists so the `[project.entry-points."nexus_eval_runners"]`
entry resolves cleanly. Importing the framework's `EvalRunner` Protocol
guarantees the eventual class will satisfy the type expected by
`eval-framework run`.
"""

from __future__ import annotations


class RuntimeThreatEvalRunner:
    """Placeholder — replaced by D.3 Task 13."""

    @property
    def agent_name(self) -> str:
        return "runtime_threat"
