"""`Gate` config + `apply_gate(suite, gate, *, baseline)` — CI thresholds.

Per F.2 plan Task 9. Gate failures are explainable strings so a CI log
points at the threshold that blew. Each check is independent: a single
suite can fail multiple gates and every failure is reported.

Defaults are strict — `Gate()` requires 100% pass and no regressions
against a baseline (when one is supplied). Token-delta and p95-duration
ceilings are opt-in.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field

from eval_framework.compare import diff_results
from eval_framework.results import EvalResult, SuiteResult


class Gate(BaseModel):
    """CI gate — every threshold is independently enforced."""

    min_pass_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    no_regressions_vs_baseline: bool = True
    max_token_delta_pct: float | None = None
    max_p95_duration_sec: float | None = None

    model_config = ConfigDict(frozen=True)


class GateResult(BaseModel):
    """Outcome of running a `Gate` against a suite (and optional baseline)."""

    passed: bool
    failures: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


# ---------------------------- internals ----------------------------------


def _total_tokens(result: EvalResult) -> int:
    return sum(c.input_tokens + c.output_tokens for c in result.trace.llm_calls)


def _suite_total_tokens(suite: SuiteResult) -> int:
    return sum(_total_tokens(c) for c in suite.cases)


def _p95(values: list[float]) -> float:
    """Linear-interpolation 95th percentile. Returns 0.0 for an empty list."""
    if not values:
        return 0.0
    sorted_values = sorted(values)
    n = len(sorted_values)
    if n == 1:
        return sorted_values[0]
    rank = 0.95 * (n - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[low]
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (rank - low)


def apply_gate(
    suite: SuiteResult,
    gate: Gate,
    *,
    baseline: SuiteResult | None = None,
) -> GateResult:
    """Run every applicable gate check; return the aggregated result.

    A gate that needs a baseline (regressions, token-delta) is silently
    skipped when `baseline` is None — the caller decides whether the
    absence of a baseline is itself a failure.
    """
    failures: list[str] = []

    # Pass rate.
    if suite.pass_rate < gate.min_pass_rate:
        failures.append(
            f"pass_rate {suite.pass_rate:.3f} < min_pass_rate {gate.min_pass_rate:.3f} "
            f"({suite.passed}/{suite.total} cases passed)"
        )

    # Regressions vs baseline.
    if gate.no_regressions_vs_baseline and baseline is not None:
        report = diff_results(baseline, suite)
        regressions = [d for d in report.case_diffs if d.status == "newly_failing"]
        if regressions:
            ids = ", ".join(d.case_id for d in regressions)
            failures.append(
                f"{len(regressions)} regression(s) vs baseline {baseline.suite_id}: {ids}"
            )

    # Token-delta vs baseline.
    if gate.max_token_delta_pct is not None and baseline is not None:
        baseline_tokens = _suite_total_tokens(baseline)
        candidate_tokens = _suite_total_tokens(suite)
        if baseline_tokens > 0:
            delta_pct = (candidate_tokens - baseline_tokens) / baseline_tokens
            if delta_pct > gate.max_token_delta_pct:
                failures.append(
                    f"token usage grew {delta_pct:.1%} (baseline {baseline_tokens}, "
                    f"candidate {candidate_tokens}); gate cap {gate.max_token_delta_pct:.1%}"
                )

    # p95 duration.
    if gate.max_p95_duration_sec is not None and suite.cases:
        p95 = _p95([c.duration_sec for c in suite.cases])
        if p95 > gate.max_p95_duration_sec:
            failures.append(f"p95 duration {p95:.2f}s > cap {gate.max_p95_duration_sec:.2f}s")

    return GateResult(passed=not failures, failures=failures)
