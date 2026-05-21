"""Scorecard delta engine — Stage 4 DELTA helper.

Pure-function diffs between the current run's Scorecards and the
previous run's Scorecards (loaded by the driver from SemanticStore
via Task 8's kg_writer). When no prior run exists for an agent, the
resulting delta is marked ``is_first_run=True`` with
``previous_pass_rate=None`` and ``delta_pct=0.0`` — first-run rows
never count as regressions (the v0.1 regression threshold in
Task 7 reads ``delta_pct`` directly and a 0.0 delta is below the
≥5% threshold).

When either side's pass_rate is None (the per-agent run errored),
``delta_pct`` is 0.0 by convention — there's no meaningful delta to
compute. ``is_comparable`` on the resulting ScorecardDelta will be
False; Task 7 must consult that flag before flagging regressions.

**Read-only.** No file I/O, no fabric, no NLAH writes. Pure
functions over pydantic models.
"""

from __future__ import annotations

from collections.abc import Sequence

from meta_harness.schemas import Scorecard, ScorecardDelta


def compute_delta(current: Scorecard, previous: Scorecard | None) -> ScorecardDelta:
    """Diff one current Scorecard against an optional previous one.

    Args:
        current: The current run's Scorecard for the agent.
        previous: The previous run's Scorecard for the same agent,
            or ``None`` if no prior run exists.

    Raises:
        ValueError: when ``previous`` is not None and its
            ``agent_id`` differs from ``current.agent_id``.
    """
    if previous is not None and previous.agent_id != current.agent_id:
        raise ValueError(
            f"agent_id mismatch: current={current.agent_id!r} previous={previous.agent_id!r}"
        )

    if previous is None:
        return ScorecardDelta(
            agent_id=current.agent_id,
            previous_pass_rate=None,
            current_pass_rate=current.pass_rate,
            delta_pct=0.0,
            is_first_run=True,
        )

    if current.pass_rate is None or previous.pass_rate is None:
        return ScorecardDelta(
            agent_id=current.agent_id,
            previous_pass_rate=previous.pass_rate,
            current_pass_rate=current.pass_rate,
            delta_pct=0.0,
            is_first_run=False,
        )

    delta_pct = (current.pass_rate - previous.pass_rate) * 100.0
    # Bound to the schema's [-100, +100] range (already guaranteed
    # by Scorecard.pass_rate's [0, 1] bound, but defensive).
    delta_pct = max(-100.0, min(100.0, delta_pct))

    return ScorecardDelta(
        agent_id=current.agent_id,
        previous_pass_rate=previous.pass_rate,
        current_pass_rate=current.pass_rate,
        delta_pct=delta_pct,
        is_first_run=False,
    )


def compute_batch_deltas(
    current_scorecards: Sequence[Scorecard],
    previous_scorecards: Sequence[Scorecard],
) -> tuple[ScorecardDelta, ...]:
    """One ScorecardDelta per current scorecard.

    Previous scorecards are matched by ``agent_id``. A current
    agent without a previous match yields a first-run delta;
    previous agents not present in current are silently dropped
    (current is the source of truth for which agents A.4 ran this
    cycle).

    Order matches ``current_scorecards``.
    """
    prev_by_agent = {sc.agent_id: sc for sc in previous_scorecards}
    return tuple(
        compute_delta(current, prev_by_agent.get(current.agent_id))
        for current in current_scorecards
    )


__all__ = ["compute_batch_deltas", "compute_delta"]
