"""Regression flagger — pure-function consumer of ``ScorecardDelta``.

Surfaces RegressionFlag entries for agents whose pass-rate dropped
by at least ``REGRESSION_THRESHOLD_PCT`` (default: 5%) since the
prior run. Used by Task 9's reporter to populate the
``regressions_flagged`` tuple on ``MetaHarnessReport``.

**Threshold semantics.**

- ``delta_pct`` is in percentage-point units (current% - prev%).
- A regression is ``delta_pct <= -REGRESSION_THRESHOLD_PCT`` —
  the comparison is *<=* (not strictly *<*) so the boundary 5%
  drop is itself flagged. Mirrors the conservative-by-default
  convention used by the rest of the platform's threshold logic
  (Q6 reviewer uses *<=* in the same way).

**First-run + non-comparable rows are never flagged.** Either side
``pass_rate=None`` -> ``is_comparable=False`` -> filter drops the
row before threshold check. ``is_first_run=True`` rows likewise
short-circuit at the filter stage.

**Read-only.** Pure function over pydantic models; no I/O.
"""

from __future__ import annotations

from collections.abc import Sequence

from meta_harness.schemas import RegressionFlag, ScorecardDelta

REGRESSION_THRESHOLD_PCT = 5.0


def flag_regressions(
    deltas: Sequence[ScorecardDelta],
    *,
    threshold_pct: float = REGRESSION_THRESHOLD_PCT,
) -> tuple[RegressionFlag, ...]:
    """Return one RegressionFlag per agent crossing the threshold.

    Args:
        deltas: Per-agent ScorecardDelta rows (one per agent the
            current run produced).
        threshold_pct: Pass-rate drop in percentage points that
            triggers a flag. Default 5.0. Tests can pass a smaller
            value to exercise edge cases.

    Returns:
        A tuple of RegressionFlag entries; order matches the input
        ``deltas`` filtered to those crossing the threshold.

    Raises:
        ValueError: when ``threshold_pct`` is not strictly positive.
    """
    if threshold_pct <= 0.0:
        raise ValueError(
            f"threshold_pct must be > 0 (got {threshold_pct}). "
            "A zero or negative threshold would flag all rows."
        )

    flags: list[RegressionFlag] = []
    for delta in deltas:
        if not delta.is_comparable:
            continue
        if delta.is_first_run:
            continue
        if delta.delta_pct > -threshold_pct:
            continue
        # Narrow the Optional fields. is_comparable guarantees both
        # rates are non-None.
        prev = delta.previous_pass_rate
        curr = delta.current_pass_rate
        assert prev is not None  # noqa: S101 — narrowed by is_comparable
        assert curr is not None  # noqa: S101
        flags.append(
            RegressionFlag(
                agent_id=delta.agent_id,
                previous_pass_rate=prev,
                current_pass_rate=curr,
                delta_pct=delta.delta_pct,
            )
        )
    return tuple(flags)


__all__ = ["REGRESSION_THRESHOLD_PCT", "flag_regressions"]
