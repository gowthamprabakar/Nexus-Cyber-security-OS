"""`diff_results` — produce a ComparisonReport between two SuiteResults.

Per F.2 plan Task 8. Case-id-keyed left-outer-join over baseline and
candidate; each pair classified as `unchanged_pass`, `unchanged_fail`,
`newly_failing`, or `newly_passing`. Cases present in only one side are
emitted with `dropped` / `added` statuses so a caller doesn't lose
coverage drift in the diff.

Token/duration deltas are computed when both sides have a record. The
token figure sums every LLM call in the case's trace; the duration is the
case-level `EvalResult.duration_sec`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from eval_framework.results import EvalResult, SuiteResult

CaseStatus = Literal[
    "unchanged_pass",
    "unchanged_fail",
    "newly_failing",
    "newly_passing",
    "dropped",
    "added",
]


class CaseDiff(BaseModel):
    """One row of a `ComparisonReport`."""

    case_id: str
    baseline_passed: bool
    candidate_passed: bool
    status: CaseStatus
    actuals_changed: bool
    token_delta: int | None
    duration_delta_sec: float

    model_config = ConfigDict(frozen=True)


class ComparisonSummary(BaseModel):
    """Aggregate counts across the case diffs."""

    total_cases: int
    regressions_count: int
    improvements_count: int
    pass_rate_delta: float

    model_config = ConfigDict(frozen=True)


class ComparisonReport(BaseModel):
    """The result of `diff_results(baseline, candidate)`."""

    baseline_suite_id: str
    candidate_suite_id: str
    baseline_provider_id: str | None
    candidate_provider_id: str | None
    case_diffs: list[CaseDiff]
    summary: ComparisonSummary

    model_config = ConfigDict(frozen=True)


# ---------------------------- internals ----------------------------------


def _total_tokens(result: EvalResult) -> int:
    return sum(c.input_tokens + c.output_tokens for c in result.trace.llm_calls)


def _classify(baseline: EvalResult, candidate: EvalResult) -> CaseStatus:
    if baseline.passed and candidate.passed:
        return "unchanged_pass"
    if not baseline.passed and not candidate.passed:
        return "unchanged_fail"
    return "newly_passing" if candidate.passed else "newly_failing"


def _diff_pair(baseline: EvalResult, candidate: EvalResult) -> CaseDiff:
    baseline_tokens = _total_tokens(baseline)
    candidate_tokens = _total_tokens(candidate)
    has_tokens = bool(baseline.trace.llm_calls or candidate.trace.llm_calls)

    return CaseDiff(
        case_id=candidate.case_id,
        baseline_passed=baseline.passed,
        candidate_passed=candidate.passed,
        status=_classify(baseline, candidate),
        actuals_changed=baseline.actuals != candidate.actuals,
        token_delta=(candidate_tokens - baseline_tokens) if has_tokens else None,
        duration_delta_sec=candidate.duration_sec - baseline.duration_sec,
    )


def _orphan_diff(case: EvalResult, *, side: Literal["dropped", "added"]) -> CaseDiff:
    return CaseDiff(
        case_id=case.case_id,
        baseline_passed=case.passed if side == "dropped" else False,
        candidate_passed=case.passed if side == "added" else False,
        status=side,
        actuals_changed=False,
        token_delta=None,
        duration_delta_sec=0.0,
    )


def diff_results(baseline: SuiteResult, candidate: SuiteResult) -> ComparisonReport:
    """Compare two SuiteResults case-by-case.

    The result preserves baseline order: cases that exist only in candidate
    are appended at the end in candidate order.
    """
    baseline_by_id = {c.case_id: c for c in baseline.cases}
    candidate_by_id = {c.case_id: c for c in candidate.cases}

    case_diffs: list[CaseDiff] = []
    for case in baseline.cases:
        cand = candidate_by_id.get(case.case_id)
        if cand is None:
            case_diffs.append(_orphan_diff(case, side="dropped"))
        else:
            case_diffs.append(_diff_pair(case, cand))

    for case in candidate.cases:
        if case.case_id not in baseline_by_id:
            case_diffs.append(_orphan_diff(case, side="added"))

    regressions = sum(1 for d in case_diffs if d.status == "newly_failing")
    improvements = sum(1 for d in case_diffs if d.status == "newly_passing")

    summary = ComparisonSummary(
        total_cases=len(case_diffs),
        regressions_count=regressions,
        improvements_count=improvements,
        pass_rate_delta=candidate.pass_rate - baseline.pass_rate,
    )

    return ComparisonReport(
        baseline_suite_id=baseline.suite_id,
        candidate_suite_id=candidate.suite_id,
        baseline_provider_id=baseline.provider_id,
        candidate_provider_id=candidate.provider_id,
        case_diffs=case_diffs,
        summary=summary,
    )
