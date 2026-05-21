"""Single-agent A/B comparison engine — Stage 3 AB_COMPARE helper.

Runs one agent's eval suite under two NLAH variants, diffs the
per-case outcomes, and produces an
``meta_harness.schemas.ABComparison``. v0.1 ships single-agent A/B
only; cross-agent A/B (variant of agent X tested against variant of
agent Y) is deferred to A.4 v0.2.

**WI-3 acceptance.** The top-level ``byte_equal`` flag is True iff
every per-case serialized RunOutcome is byte-equal across variants.
Under stub-LLM mode + identical NLAH, this MUST be True; any drift
signals a hidden non-determinism source.

**Mechanism.** The NLAH-override context patches
``charter.nlah_loader.default_nlah_dir`` to redirect every per-agent
call to the override path. Since every agent uses
``default_nlah_dir(__file__)`` to discover its NLAH dir, the patch
swaps the variant in for the duration of one suite run, then
restores the original. Process-wide; single-agent A/B is the v0.1
contract.

**Read-only contract (WI-4).** The override target is read only via
``charter.nlah_loader.load_system_prompt`` and the agent's
existing eval-runner machinery — no write surface introduced.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Protocol

from charter import nlah_loader
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase, load_cases
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite

from meta_harness.eval.batch import _instantiate_runner
from meta_harness.schemas import ABComparison, ABComparisonCaseDelta

_ENTRY_POINT_GROUP = "nexus_eval_runners"


class CasesResolver(Protocol):
    """Maps an ``agent_id`` to its bundled ``eval/cases/`` directory."""

    def __call__(self, agent_id: str) -> Path: ...


@dataclass(frozen=True)
class ABCompareRequest:
    """Inputs to one A/B run."""

    customer_id: str
    run_id: str
    agent_id: str
    variant_a_path: Path
    variant_b_path: Path
    llm_provider: LLMProvider | None = None


class ABCompareError(ValueError):
    """Raised when an A/B request is malformed (e.g., identical variants)."""


@contextlib.contextmanager
def nlah_override(target_dir: Path) -> Iterator[None]:
    """Patch ``charter.nlah_loader.default_nlah_dir`` to return ``target_dir``.

    Every agent that calls ``default_nlah_dir(__file__)`` for its
    NLAH directory will receive ``target_dir`` instead while the
    context is active. The original function is restored on exit
    (including under exception).

    The override target must be an existing directory containing a
    valid NLAH layout (``README.md`` required). Validation happens
    at the override site, not here — ``load_system_prompt`` will
    raise ``FileNotFoundError`` if the layout is invalid.
    """
    target_dir = Path(target_dir)
    if not target_dir.is_dir():
        raise ABCompareError(f"NLAH override target is not a directory: {target_dir}")

    original = nlah_loader.default_nlah_dir

    def _redirect(package_file: str | Path) -> Path:
        del package_file  # the override forces a single target
        return target_dir

    nlah_loader.default_nlah_dir = _redirect
    try:
        yield
    finally:
        nlah_loader.default_nlah_dir = original


def compare_results(
    suite_a: SuiteResult,
    suite_b: SuiteResult,
) -> tuple[ABComparisonCaseDelta, ...]:
    """Diff two SuiteResults case-by-case.

    Matches cases by ``case_id``; cases present in only one suite
    produce a delta with the missing-variant marked as failed and
    ``byte_equal=False``. Output preserves the ordering of
    ``suite_a.cases`` and appends any A-missing cases at the end.
    """
    by_id_b: dict[str, EvalResult] = {r.case_id: r for r in suite_b.cases}

    deltas: list[ABComparisonCaseDelta] = []
    seen: set[str] = set()
    for result_a in suite_a.cases:
        seen.add(result_a.case_id)
        result_b = by_id_b.get(result_a.case_id)
        deltas.append(_case_delta(result_a, result_b))

    for result_b in suite_b.cases:
        if result_b.case_id in seen:
            continue
        deltas.append(_case_delta(None, result_b))

    return tuple(deltas)


def _case_delta(a: EvalResult | None, b: EvalResult | None) -> ABComparisonCaseDelta:
    if a is not None:
        case_id = a.case_id
    elif b is not None:
        case_id = b.case_id
    else:
        raise ValueError("_case_delta requires at least one non-None result")
    return ABComparisonCaseDelta(
        case_id=case_id,
        variant_a_passed=bool(a is not None and a.passed),
        variant_b_passed=bool(b is not None and b.passed),
        byte_equal=_byte_equal(a, b),
    )


def _byte_equal(a: EvalResult | None, b: EvalResult | None) -> bool:
    """True iff both results serialize to identical JSON bytes.

    A missing result on either side is treated as not byte-equal —
    a missing-case is itself a behavioral divergence the report
    should surface.
    """
    if a is None or b is None:
        return False
    return _canonical_bytes(a) == _canonical_bytes(b)


def _canonical_bytes(result: EvalResult) -> bytes:
    """Serialize an EvalResult to canonical JSON bytes.

    Strips fields that legitimately vary across runs even under
    identical inputs (``duration_sec``; trace timestamps).
    """
    payload = {
        "case_id": result.case_id,
        "runner": result.runner,
        "passed": result.passed,
        "failure_reason": result.failure_reason,
        "actuals": result.actuals,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def run_variant(
    *,
    agent_id: str,
    variant_path: Path,
    cases: list[EvalCase],
    llm_provider: LLMProvider | None,
) -> SuiteResult:
    """Run ``agent_id``'s eval suite once with the NLAH override applied."""
    runner: EvalRunner = _resolve_runner(agent_id)
    with nlah_override(variant_path):
        return await run_suite(cases, runner, llm_provider=llm_provider)


def _resolve_runner(agent_id: str) -> EvalRunner:
    """Find the entry point for ``agent_id`` and instantiate its runner."""
    eps: list[EntryPoint] = list(entry_points(group=_ENTRY_POINT_GROUP))
    for ep in eps:
        if ep.name == agent_id:
            return _instantiate_runner(ep)
    raise ABCompareError(f"no nexus_eval_runners entry point named {agent_id!r}")


async def ab_compare(
    request: ABCompareRequest,
    *,
    cases_resolver: CasesResolver,
) -> ABComparison:
    """End-to-end A/B run for a single agent.

    Loads the agent's eval cases once, runs the suite twice (once
    per variant) with the NLAH override applied, diffs the results,
    and assembles the ABComparison.
    """
    if request.variant_a_path == request.variant_b_path:
        raise ABCompareError("variant_a_path and variant_b_path must differ")

    cases_dir = cases_resolver(request.agent_id)
    cases = load_cases(cases_dir)

    suite_a = await run_variant(
        agent_id=request.agent_id,
        variant_path=request.variant_a_path,
        cases=cases,
        llm_provider=request.llm_provider,
    )
    suite_b = await run_variant(
        agent_id=request.agent_id,
        variant_path=request.variant_b_path,
        cases=cases,
        llm_provider=request.llm_provider,
    )

    per_case = compare_results(suite_a, suite_b)
    overall_byte_equal = all(d.byte_equal for d in per_case) if per_case else True

    total_a = len(suite_a.cases)
    total_b = len(suite_b.cases)
    pass_rate_a = (sum(1 for r in suite_a.cases if r.passed) / total_a) if total_a else 1.0
    pass_rate_b = (sum(1 for r in suite_b.cases if r.passed) / total_b) if total_b else 1.0

    return ABComparison(
        customer_id=request.customer_id,
        run_id=request.run_id,
        agent_id=request.agent_id,
        variant_a_path=str(request.variant_a_path),
        variant_b_path=str(request.variant_b_path),
        variant_a_pass_rate=pass_rate_a,
        variant_b_pass_rate=pass_rate_b,
        per_case_deltas=per_case,
        byte_equal=overall_byte_equal,
        evaluated_at=datetime.now(UTC),
    )


__all__ = [
    "ABCompareError",
    "ABCompareRequest",
    "CasesResolver",
    "ab_compare",
    "compare_results",
    "nlah_override",
    "run_variant",
]
