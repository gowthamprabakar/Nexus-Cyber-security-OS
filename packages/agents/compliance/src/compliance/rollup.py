"""PASS+FAIL roll-up aggregation (compliance v0.2 Task 8).

Classifies each control as **pass** / **fail** / **not_evaluated** and rolls the result up
per framework. A control aggregates across **all** its mapped source rules (the multi-emitter
pattern — e.g. CIS-K8s 5.2.2 maps to a kube-bench result + a runtime rule): any failing
mapped rule fails the control; all-evaluated-and-none-failing passes it; otherwise its
status is unknown (not_evaluated). Coverage % counts only the controls with a determinable
status, so a sparsely-emitted framework reports honestly low coverage rather than fake PASS.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

PASS = "pass"  # noqa: S105 — a control status literal, not a secret
FAIL = "fail"
NOT_EVALUATED = "not_evaluated"


def classify_control(
    mapped_rule_ids: Iterable[str], *, evaluated: set[str], failing: set[str]
) -> str:
    """Classify one control from its mapped rule ids + the evaluated/failing rule sets."""
    mapped = set(mapped_rule_ids)
    if not mapped:
        return NOT_EVALUATED  # unwired — no evidence either way
    if not mapped.isdisjoint(failing):
        return FAIL  # any failing mapped rule fails the control (multi-emitter aggregation)
    if mapped <= evaluated:
        return PASS  # every mapped rule ran + none failed
    return NOT_EVALUATED  # a mapped rule never ran → unknown


@dataclass(frozen=True, slots=True)
class FrameworkRollup:
    framework: str
    pass_count: int
    fail_count: int
    not_evaluated_count: int

    @property
    def total_controls(self) -> int:
        return self.pass_count + self.fail_count + self.not_evaluated_count

    @property
    def determinable(self) -> int:
        return self.pass_count + self.fail_count

    @property
    def coverage_pct(self) -> float:
        """Percent of controls with a determinable (pass/fail) status."""
        total = self.total_controls
        return round(100.0 * self.determinable / total, 1) if total else 0.0


def roll_up_framework(
    framework: str,
    controls: Sequence[tuple[str, Iterable[str]]],
    *,
    evaluated: set[str],
    failing: set[str],
) -> FrameworkRollup:
    """Roll up a framework from ``(control_id, mapped_rule_ids)`` pairs."""
    statuses = [classify_control(m, evaluated=evaluated, failing=failing) for _, m in controls]
    return FrameworkRollup(
        framework=framework,
        pass_count=statuses.count(PASS),
        fail_count=statuses.count(FAIL),
        not_evaluated_count=statuses.count(NOT_EVALUATED),
    )
