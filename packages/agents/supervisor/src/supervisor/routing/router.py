"""Pure-function routing rule engine — Stage 2 ROUTE.

Takes an ``IncomingTask`` envelope (metadata-only — never the
OCSF body per WI-4) plus a tuple of ``RoutingRule`` and returns
a ``RoutingDecision`` tagged-union variant.

**Match precedence** (per plan Q2):

1. ``target_agent_declared`` — explicit routing wins when the
   task's ``target_agent`` field is set.
2. ``task_type_pattern`` — pattern-match fallback on ``task_type``.
3. ``delta_type_pattern`` — pattern-match fallback on ``delta_type``.

``priority`` (higher wins) breaks ties when multiple rules match
the same task. **Equal priority + multiple matches at the same
precedence level -> ``Ambiguous`` decision** (escalate).

**No LLM call anywhere.** Pure-function over pydantic + frozen
strings. Smoke-test source-grep guard catches accidental imports.

**No OCSF payload reads.** Router only inspects the four envelope
keys on ``IncomingTask`` (``target_agent`` / ``task_type`` /
``delta_type`` / ``priority`` for context). WI-4 sub-clause.
"""

from __future__ import annotations

from collections.abc import Sequence

from supervisor.schemas import (
    IncomingTask,
    RoutingAmbiguous,
    RoutingDecision,
    RoutingMatch,
    RoutingNoMatch,
    RoutingRule,
)


def route(
    task: IncomingTask,
    rules: Sequence[RoutingRule],
) -> RoutingDecision:
    """Match ``task`` against ``rules`` and return a RoutingDecision.

    Match precedence:

    1. ``target_agent_declared`` (explicit routing).
    2. ``task_type_pattern`` (pattern-match fallback).
    3. ``delta_type_pattern`` (delta-match fallback).

    For each precedence level we collect all rules that match,
    then filter to the highest ``priority`` value. If exactly one
    rule remains at that priority, we return a ``Match``. If two
    or more remain at the same priority, we return ``Ambiguous``.
    If no rule matches at this precedence level, we fall through
    to the next.

    If no rule matches at any precedence level, we return
    ``NoMatch``.

    The ``Escalate`` variant is reserved for an explicit operator
    decision (e.g., a rule whose ``target_agent == "escalate"``);
    v0.1 does not synthesise it from match logic. Operators wire
    it via a special-purpose rule in a future ``agents.md`` update.
    """
    for matcher in (_match_explicit, _match_task_type, _match_delta_type):
        candidates = matcher(task, rules)
        if not candidates:
            continue
        return _resolve(candidates)
    return RoutingNoMatch(reason=_no_match_reason(task))


def _match_explicit(
    task: IncomingTask,
    rules: Sequence[RoutingRule],
) -> list[RoutingRule]:
    if not task.target_agent:
        return []
    return [r for r in rules if r.target_agent_declared == task.target_agent]


def _match_task_type(
    task: IncomingTask,
    rules: Sequence[RoutingRule],
) -> list[RoutingRule]:
    if not task.task_type:
        return []
    return [r for r in rules if r.task_type_pattern == task.task_type]


def _match_delta_type(
    task: IncomingTask,
    rules: Sequence[RoutingRule],
) -> list[RoutingRule]:
    if not task.delta_type:
        return []
    return [r for r in rules if r.delta_type_pattern == task.delta_type]


def _resolve(candidates: list[RoutingRule]) -> RoutingDecision:
    """Pick the highest-priority rule; flag ties as Ambiguous."""
    highest = max(r.priority for r in candidates)
    top = [r for r in candidates if r.priority == highest]
    if len(top) == 1:
        rule = top[0]
        return RoutingMatch(
            rule_id=rule.rule_id,
            target_agent=rule.target_agent,
            permitted_tools=rule.permitted_tools,
        )
    return RoutingAmbiguous(
        candidate_rule_ids=tuple(r.rule_id for r in top),
        reason=(
            f"{len(top)} rules matched at priority={highest}: {', '.join(r.rule_id for r in top)}"
        ),
    )


def _no_match_reason(task: IncomingTask) -> str:
    parts: list[str] = []
    if task.target_agent:
        parts.append(f"target_agent={task.target_agent!r}")
    if task.task_type:
        parts.append(f"task_type={task.task_type!r}")
    if task.delta_type:
        parts.append(f"delta_type={task.delta_type!r}")
    if not parts:
        return "incoming task has no routing keys (target_agent / task_type / delta_type all unset)"
    return f"no rule matched task with {', '.join(parts)}"


__all__ = ["route"]
