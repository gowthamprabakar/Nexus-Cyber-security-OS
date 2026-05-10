"""`EvalRunner` Protocol — every agent's eval runner satisfies this shape.

The framework's `run_suite(...)` (Task 5) accepts any object that satisfies
`EvalRunner` and orchestrates suite execution. Per-agent runners (Task 7's
`CloudPostureEvalRunner`, future agents' equivalents) live in their own
packages and register via the setuptools entry-point group
`nexus_eval_runners` so the CLI (Task 13) can resolve them by name.

The Protocol is `@runtime_checkable` so callers / tests can do
`isinstance(runner, EvalRunner)` without importing each concrete class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from charter.llm import LLMProvider

from eval_framework.cases import EvalCase

# Per-call return shape: (passed, failure_reason, actuals, audit_log_path).
# Wrapped into an `EvalResult` by `run_suite` (which adds case_id, runner
# name, duration, trace).
RunOutcome = tuple[bool, str | None, dict[str, Any], Path | None]


@runtime_checkable
class EvalRunner(Protocol):
    """The integration boundary every agent's eval runner satisfies."""

    @property
    def agent_name(self) -> str:
        """Stable identifier (e.g. `"cloud_posture"`). Becomes
        `EvalResult.runner` and `SuiteResult.runner`."""

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        """Run one case. Return (passed, failure_reason, actuals, audit_log_path).

        - `workspace` is a fresh per-case directory the runner may write into.
        - `llm_provider` is `None` for deterministic runs; otherwise the
          runner threads it through to the agent under test.
        - The framework wraps the return tuple into an `EvalResult` after
          adding case_id, runner name, duration, and trace (parsed from
          the audit log if present).
        """


# ---------------------------- FakeRunner ----------------------------------


@dataclass
class _QueuedResponse:
    passed: bool
    failure_reason: str | None
    actuals: dict[str, Any]
    audit_log_path: Path | None


@dataclass
class FakeRunner:
    """Deterministic test double for `EvalRunner`.

    Use `queue(case_id, ...)` to set the response for a specific case_id.
    Cases without a queued response fall through to a default that returns
    `default_passed` (with a stock failure_reason if `default_passed=False`).

    `calls` records each `EvalCase` the runner saw, in order.
    """

    agent_name: str = "fake"
    default_passed: bool = True
    _queue: dict[str, _QueuedResponse] = field(default_factory=dict, init=False)
    calls: list[EvalCase] = field(default_factory=list, init=False)

    def queue(
        self,
        case_id: str,
        *,
        passed: bool,
        failure_reason: str | None = None,
        actuals: dict[str, Any] | None = None,
        audit_log_path: Path | None = None,
    ) -> None:
        self._queue[case_id] = _QueuedResponse(
            passed=passed,
            failure_reason=failure_reason,
            actuals=dict(actuals or {}),
            audit_log_path=audit_log_path,
        )

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        del workspace, llm_provider  # the fake doesn't need these
        self.calls.append(case)
        if case.case_id in self._queue:
            r = self._queue[case.case_id]
            return r.passed, r.failure_reason, dict(r.actuals), r.audit_log_path
        if self.default_passed:
            return True, None, {}, None
        return False, "no queued response and default_passed is False", {}, None
