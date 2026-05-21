"""Agent-local ``BatchEvalRunner`` — Stage 2 BATCH_EVAL helper.

Iterates over every registered ``nexus_eval_runners`` entry-point,
loads each agent's bundled ``eval/cases/*.yaml`` via
``eval_framework.cases.load_cases``, runs the suite via
``eval_framework.suite.run_suite``, and produces one
``meta_harness.schemas.Scorecard`` per agent.

**Per ADR-007's 3rd-consumer hoist rule (Q-ARCH-3):** this lives
agent-local in v0.1. If Supervisor #0 (or any other future agent)
becomes the third consumer of a batch-eval primitive, hoist to
``packages/eval-framework/`` at that point with a one-paragraph
rationale in the hoist PR.

**Per Task 4 risk-mitigation row:** one agent's per-run failure
(import error, missing cases dir, runner raises) must not poison
the batch. Failures surface as ``Scorecard(pass_rate=None,
error=<short message>)`` and the loop continues.

**Q-ARCH-2 reminder.** No bus / subject reference appears here;
no per-agent state mutation; no NLAH writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Protocol

from charter.llm import LLMProvider
from eval_framework.cases import load_cases
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite

from meta_harness.schemas import Scorecard

_ENTRY_POINT_GROUP = "nexus_eval_runners"


class CasesRootResolver(Protocol):
    """Maps an ``agent_id`` to its ``eval/cases/`` directory.

    The default resolver assumes the workspace convention
    ``packages/agents/<agent>/eval/cases/``. Tests inject a custom
    resolver to point at synthetic case directories under
    ``tmp_path``.
    """

    def __call__(self, agent_id: str) -> Path: ...


def default_cases_root(workspace_root: Path) -> CasesRootResolver:
    """Return a resolver that picks ``<workspace_root>/packages/agents/<agent>/eval/cases``.

    Used by the agent driver (Task 10) and the CLI (Task 13) so the
    workspace convention lives in one place.
    """

    def _resolve(agent_id: str) -> Path:
        return workspace_root / "packages" / "agents" / _agent_dirname(agent_id) / "eval" / "cases"

    return _resolve


def _agent_dirname(agent_id: str) -> str:
    """Convert a snake_case agent_id (``cloud_posture``) into the
    hyphenated directory name used on disk (``cloud-posture``).

    The convention every shipped agent follows.
    """
    return agent_id.replace("_", "-")


@dataclass(frozen=True)
class BatchEvalConfig:
    """Knobs the batch runner exposes to callers.

    ``agent_filter``: when non-empty, only entry points whose name
    appears in the set are run. The default empty set runs every
    discovered runner.

    ``llm_provider``: threaded into each ``run_suite`` invocation.
    Tests pass ``None``; the live driver threads its stub provider.
    """

    agent_filter: frozenset[str] = frozenset()
    llm_provider: LLMProvider | None = None


class BatchEvalRunner:
    """Sequential cross-agent batch eval orchestrator."""

    def __init__(
        self,
        *,
        cases_root: CasesRootResolver,
        config: BatchEvalConfig | None = None,
    ) -> None:
        self._cases_root = cases_root
        self._config = config or BatchEvalConfig()

    async def run_batch(
        self,
        *,
        customer_id: str,
        run_id: str,
    ) -> list[Scorecard]:
        """Run every registered runner and return one Scorecard each.

        Per-agent exceptions are caught and surface as a failing
        Scorecard (pass_rate=None, error=str(exc)); the batch
        continues to the next runner.
        """
        scorecards: list[Scorecard] = []
        for ep in self._discover_entry_points():
            scorecards.append(await self._run_one_agent(ep, customer_id=customer_id, run_id=run_id))
        return scorecards

    def _discover_entry_points(self) -> list[EntryPoint]:
        """Return every entry point in ``nexus_eval_runners`` that passes the filter."""
        eps = entry_points(group=_ENTRY_POINT_GROUP)
        filtered: list[EntryPoint] = []
        for ep in eps:
            if self._config.agent_filter and ep.name not in self._config.agent_filter:
                continue
            filtered.append(ep)
        # Stable ordering so Scorecard sequence is deterministic
        # across runs / machines.
        filtered.sort(key=lambda ep: ep.name)
        return filtered

    async def _run_one_agent(
        self,
        ep: EntryPoint,
        *,
        customer_id: str,
        run_id: str,
    ) -> Scorecard:
        evaluated_at = datetime.now(UTC)
        try:
            runner = _instantiate_runner(ep)
            cases_dir = self._cases_root(ep.name)
            cases = load_cases(cases_dir)
        except Exception as exc:
            return Scorecard(
                customer_id=customer_id,
                run_id=run_id,
                agent_id=ep.name,
                total_cases=0,
                passed=0,
                failed=0,
                error=_short_error(exc),
                evaluated_at=evaluated_at,
            )

        if not cases:
            # An agent that registers but ships zero YAML cases is
            # legal (e.g. a v0.1 agent with eval suite still in
            # flight). Surface a non-error, zero-cases scorecard at
            # pass_rate=1.0 so it doesn't drag the batch average.
            return Scorecard(
                customer_id=customer_id,
                run_id=run_id,
                agent_id=ep.name,
                total_cases=0,
                passed=0,
                failed=0,
                pass_rate=1.0,
                evaluated_at=evaluated_at,
            )

        try:
            suite_result = await run_suite(
                cases,
                runner,
                llm_provider=self._config.llm_provider,
            )
        except Exception as exc:
            return Scorecard(
                customer_id=customer_id,
                run_id=run_id,
                agent_id=ep.name,
                total_cases=len(cases),
                passed=0,
                failed=0,
                error=_short_error(exc),
                evaluated_at=evaluated_at,
            )

        total = len(suite_result.cases)
        passed = sum(1 for r in suite_result.cases if r.passed)
        failed = total - passed
        pass_rate = (passed / total) if total > 0 else 1.0
        return Scorecard(
            customer_id=customer_id,
            run_id=run_id,
            agent_id=ep.name,
            total_cases=total,
            passed=passed,
            failed=failed,
            pass_rate=pass_rate,
            evaluated_at=evaluated_at,
        )


def _instantiate_runner(ep: EntryPoint) -> EvalRunner:
    """Load the entry-point's target and instantiate it.

    Most agents register a *class* (resolved via ``ep.load()``);
    instantiate with no args. If the registered object is already
    callable (a factory function returning an EvalRunner) we call
    it; if it's already an instance (rare; only the FakeRunner
    pattern in tests), we use it directly.
    """
    target = ep.load()
    if isinstance(target, type):
        return target()  # type: ignore[no-any-return]
    if callable(target):
        return target()  # type: ignore[no-any-return]
    return target  # type: ignore[no-any-return]


def _short_error(exc: BaseException) -> str:
    """Bound the error string to fit the Scorecard.error field length cap."""
    message = f"{type(exc).__name__}: {exc}"
    return message[:512]


__all__ = [
    "BatchEvalConfig",
    "BatchEvalRunner",
    "CasesRootResolver",
    "default_cases_root",
]
