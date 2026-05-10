"""`run_suite` — orchestrate one `EvalRunner` over a list of `EvalCase`s.

Per F.2 plan Task 5. Sequential execution by default; `max_concurrency`>1 is
reserved for a future task. Each case gets a fresh per-case workspace under
`workspace_root / suite_id / <case_id>-<uuid8>` so tests can inspect what
the runner wrote without races between cases. Per-case time is bounded by
`case.timeout_sec` via `asyncio.wait_for`; on timeout the case is recorded
as failed with `failure_reason="timeout after Xs"` and the suite continues.

Trace capture is intentionally minimal here: only `audit_log_path` is
populated when the runner returns one. Parsing the audit log into
`LLMCallRecord` / `ToolCallRecord` lands in F.2 Task 6.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ulid
from charter.llm import LLMProvider

from eval_framework.cases import EvalCase
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.runner import EvalRunner
from eval_framework.trace import EvalTrace, build_trace_from_audit_log


async def run_suite(
    cases: list[EvalCase],
    runner: EvalRunner,
    *,
    llm_provider: LLMProvider | None = None,
    workspace_root: Path | None = None,
    suite_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    max_concurrency: int = 1,
) -> SuiteResult:
    """Run every case through `runner` and return one `SuiteResult`.

    Args:
        cases: Cases to run. Order is preserved in the result.
        runner: An `EvalRunner` (any object satisfying the Protocol).
        llm_provider: Threaded to the runner for each case. If supplied, the
            suite's `provider_id` is set from `llm_provider.provider_id`.
        workspace_root: Parent directory for per-case workspaces. Defaults
            to a fresh `tempfile.mkdtemp` directory if not provided.
        suite_id: Caller-supplied suite identifier. A ULID is minted if
            omitted.
        metadata: Free-form metadata attached to the `SuiteResult`.
        max_concurrency: Reserved for future use. Currently must be 1.

    Returns:
        A frozen `SuiteResult` containing one `EvalResult` per case.

    Raises:
        ValueError: if `max_concurrency` != 1 (sequential-only for now).
    """
    if max_concurrency != 1:
        raise ValueError(
            f"run_suite currently supports max_concurrency=1 only (got {max_concurrency})"
        )

    sid = suite_id or str(ulid.ULID())
    root = (
        workspace_root
        if workspace_root is not None
        else Path(tempfile.mkdtemp(prefix="nexus-eval-"))
    )
    suite_dir = root / sid
    suite_dir.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(UTC)
    results: list[EvalResult] = []

    for case in cases:
        case_ws = suite_dir / f"{case.case_id}-{uuid.uuid4().hex[:8]}"
        case_ws.mkdir(parents=True, exist_ok=True)
        results.append(await _run_one(case, runner, case_ws, llm_provider))

    completed_at = datetime.now(UTC)

    return SuiteResult(
        suite_id=sid,
        runner=runner.agent_name,
        started_at=started_at,
        completed_at=completed_at,
        cases=results,
        provider_id=llm_provider.provider_id if llm_provider is not None else None,
        model_pin=None,  # populated from trace records once Task 6 lands
        metadata=dict(metadata or {}),
    )


async def _run_one(
    case: EvalCase,
    runner: EvalRunner,
    workspace: Path,
    llm_provider: LLMProvider | None,
) -> EvalResult:
    """Run a single case with timeout enforcement; never raises."""
    started = time.perf_counter()
    try:
        passed, failure_reason, actuals, audit_log_path = await asyncio.wait_for(
            runner.run(case, workspace=workspace, llm_provider=llm_provider),
            timeout=case.timeout_sec,
        )
    except TimeoutError:
        return EvalResult(
            case_id=case.case_id,
            runner=runner.agent_name,
            passed=False,
            failure_reason=f"timeout after {case.timeout_sec}s",
            actuals={},
            duration_sec=time.perf_counter() - started,
            trace=EvalTrace(),
        )

    trace = (
        build_trace_from_audit_log(audit_log_path) if audit_log_path is not None else EvalTrace()
    )

    return EvalResult(
        case_id=case.case_id,
        runner=runner.agent_name,
        passed=passed,
        failure_reason=failure_reason,
        actuals=actuals,
        duration_sec=time.perf_counter() - started,
        trace=trace,
    )


# ---------------------------- run_across_providers -------------------------


async def run_across_providers(
    cases: list[EvalCase],
    runner: EvalRunner,
    providers: dict[str, LLMProvider],
    *,
    workspace_root: Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, SuiteResult]:
    """Run the same suite against every provider in `providers`.

    Per F.2 plan Task 12; this is the substrate for ADR-003's eval-parity
    gate ("a workhorse swap must be proven on the per-agent eval suite
    before customer rollout"). Pair the returned `SuiteResult`s with
    `diff_results(...)` to surface drift.

    Returns a `dict[provider_label, SuiteResult]`. Sequential execution.
    Each provider gets an isolated `<workspace_root>/<suite_id>/...` tree
    so re-runs don't collide.
    """
    out: dict[str, SuiteResult] = {}
    for label, provider in providers.items():
        out[label] = await run_suite(
            cases,
            runner,
            llm_provider=provider,
            workspace_root=workspace_root,
            metadata=dict(metadata or {}),
        )
        del label  # provider identity already lives in SuiteResult.provider_id
    return out
