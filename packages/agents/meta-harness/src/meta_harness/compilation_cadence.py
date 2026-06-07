"""Compilation cadence controller — v0.2.5 Task 7a (brainstorm Q4).

Decides **when** an agent's DSPy compilation should run and **serializes**
compilations per agent. This module is the *decision* half of Task 7: pure
cadence logic + state persistence + signal aggregation + a per-agent lock.

It performs **no compilation**, no factory wiring, and no eval-gate calls —
those land in Task 7b (``make_dspy_candidate_factory`` + ``skill_lifecycle``
wiring + the live pipeline test).

Cadence (Q4 hybrid):

* **Event-driven** — ``EFFECTIVENESS_DROP`` (agent's average effectiveness <
  threshold), ``SKILL_THRESHOLD`` (≥ N new skills since last compile),
  ``MANUAL`` (operator-requested).
* **Scheduled** — ``WEEKLY_CRON`` (lazy timestamp check: ≥ interval days since
  the last compile, or never compiled). No background scheduler — evaluation
  happens when the caller asks (the lazy "Option A" cron, no daemon).

Decision **priority** (first match wins): ``MANUAL`` → ``EFFECTIVENESS_DROP`` →
``SKILL_THRESHOLD`` → ``WEEKLY_CRON`` → no-compile.

**Audit:** cadence decisions are operational signal, not durable state
transitions — they go to structured logs (``_LOG``), not the audit chain. The
compilation *work* Task 7b performs is audited via the existing
``candidate_emitted`` / ``eval_gate_completed`` events (no new audit constant,
per Q7).

**Lock semantics:** per-agent, per-controller-instance ``asyncio.Lock``,
**non-blocking** — ``try_acquire`` returns ``False`` immediately when a
compilation for that agent is already in flight (the second caller skips and
the legacy path proceeds; CF #2). Different agents compile concurrently.

Leaf-module discipline: imports only ``effectiveness_store`` (G1 read) + stdlib;
never ``skill_lifecycle`` / ``skill_writer`` / ``skill_eval_gate`` /
``skill_approval``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

from meta_harness.effectiveness_store import list_deployed_skills_with_scores

_LOG = logging.getLogger(__name__)

DEFAULT_EFFECTIVENESS_THRESHOLD = 0.4
DEFAULT_SKILL_COUNT_THRESHOLD = 10
DEFAULT_CRON_INTERVAL_DAYS = 7

_STATE_DIRNAME = "compilation-cadence"
_STATE_FILENAME = "state.json"


class CompilationTrigger(Enum):
    """Why a compilation cycle fired (Q4)."""

    EFFECTIVENESS_DROP = "effectiveness_drop"
    SKILL_THRESHOLD = "skill_threshold"
    MANUAL = "manual"
    WEEKLY_CRON = "weekly_cron"


@dataclass(frozen=True)
class CadenceDecision:
    """Result of evaluating cadence for one agent."""

    should_compile: bool
    trigger: CompilationTrigger | None
    reason: str  # human-readable explanation (also logged)


@dataclass(frozen=True)
class CadenceState:
    """Persisted per-agent cadence state (sidecar)."""

    agent_id: str
    last_compile_at: datetime | None
    skill_count_at_last_compile: int
    manual_trigger_pending: bool


class CompilationCadenceController:
    """Decides when an agent's DSPy compilation should run, and serializes them.

    One controller per lifecycle run. Construct with the workspace root + the
    (optional) threshold knobs; call :meth:`evaluate` per agent. After a
    compilation completes, the caller (Task 7b) calls :meth:`record_compilation`
    to advance the state.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        effectiveness_threshold: float = DEFAULT_EFFECTIVENESS_THRESHOLD,
        skill_count_threshold: int = DEFAULT_SKILL_COUNT_THRESHOLD,
        cron_interval_days: int = DEFAULT_CRON_INTERVAL_DAYS,
        tenant_id: str = "default",
    ) -> None:
        self._workspace_root = Path(workspace_root)
        self._effectiveness_threshold = effectiveness_threshold
        self._skill_count_threshold = skill_count_threshold
        self._cron_interval = timedelta(days=cron_interval_days)
        self._cron_interval_days = cron_interval_days
        self._tenant_id = tenant_id
        self._locks: dict[str, asyncio.Lock] = {}

    # --------------------------------------------------------------- state I/O

    def _state_path(self, agent_id: str) -> Path:
        return self._workspace_root / ".nexus" / _STATE_DIRNAME / agent_id / _STATE_FILENAME

    def load_state(self, agent_id: str) -> CadenceState:
        """Read the agent's cadence-state sidecar (defaults when absent)."""
        path = self._state_path(agent_id)
        if not path.is_file():
            return CadenceState(
                agent_id=agent_id,
                last_compile_at=None,
                skill_count_at_last_compile=0,
                manual_trigger_pending=False,
            )
        raw = json.loads(path.read_text(encoding="utf-8"))
        last = raw.get("last_compile_at")
        return CadenceState(
            agent_id=agent_id,
            last_compile_at=datetime.fromisoformat(last) if last else None,
            skill_count_at_last_compile=int(raw.get("skill_count_at_last_compile", 0)),
            manual_trigger_pending=bool(raw.get("manual_trigger_pending", False)),
        )

    def _write_state(self, state: CadenceState) -> None:
        path = self._state_path(state.agent_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "agent_id": state.agent_id,
                    "last_compile_at": (
                        state.last_compile_at.isoformat() if state.last_compile_at else None
                    ),
                    "skill_count_at_last_compile": state.skill_count_at_last_compile,
                    "manual_trigger_pending": state.manual_trigger_pending,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def record_compilation(self, agent_id: str, *, now: datetime | None = None) -> CadenceState:
        """Advance state after a compilation: stamp ``last_compile_at``, snapshot
        the current skill count, and clear any pending manual trigger."""
        now = now or datetime.now(UTC)
        state = CadenceState(
            agent_id=agent_id,
            last_compile_at=now,
            skill_count_at_last_compile=self.current_skill_count(agent_id),
            manual_trigger_pending=False,
        )
        self._write_state(state)
        return state

    def request_manual(self, agent_id: str) -> CadenceState:
        """Set the manual-trigger flag (operator-initiated compile request)."""
        prev = self.load_state(agent_id)
        state = CadenceState(
            agent_id=agent_id,
            last_compile_at=prev.last_compile_at,
            skill_count_at_last_compile=prev.skill_count_at_last_compile,
            manual_trigger_pending=True,
        )
        self._write_state(state)
        return state

    # ----------------------------------------------------------------- signals

    def current_skill_count(self, agent_id: str) -> int:
        """Number of deployed skills for ``agent_id`` (cadence skill-count signal)."""
        return sum(
            1
            for aid, _skill_id, _score in list_deployed_skills_with_scores(
                self._workspace_root, self._tenant_id
            )
            if aid == agent_id
        )

    def average_effectiveness(self, agent_id: str) -> float | None:
        """Mean ``global_score`` over the agent's *scored* skills.

        Skips skills with no score, zero confidence, or a missing global score
        (the same exclusion the trainset pre-filter uses). Returns ``None`` when
        no skill carries a usable score — in which case the effectiveness-drop
        trigger does not fire (no signal ≠ a low signal).
        """
        scores = [
            score.global_score
            for aid, _skill_id, score in list_deployed_skills_with_scores(
                self._workspace_root, self._tenant_id
            )
            if aid == agent_id
            and score is not None
            and score.confidence > 0.0
            and score.global_score is not None
        ]
        if not scores:
            return None
        return sum(scores) / len(scores)

    # ---------------------------------------------------------------- decision

    def evaluate(self, agent_id: str, *, now: datetime | None = None) -> CadenceDecision:
        """Decide whether ``agent_id`` should compile now (priority order)."""
        now = now or datetime.now(UTC)
        state = self.load_state(agent_id)

        decision = self._decide(agent_id, state, now)
        _LOG.info(
            "compilation_cadence.decision agent_id=%s should_compile=%s trigger=%s reason=%s",
            agent_id,
            decision.should_compile,
            decision.trigger.value if decision.trigger else None,
            decision.reason,
        )
        return decision

    def _decide(self, agent_id: str, state: CadenceState, now: datetime) -> CadenceDecision:
        # 1. Manual (operator-initiated) — highest priority.
        if state.manual_trigger_pending:
            return CadenceDecision(True, CompilationTrigger.MANUAL, "manual trigger pending")

        # 2. Effectiveness drop.
        avg = self.average_effectiveness(agent_id)
        if avg is not None and avg < self._effectiveness_threshold:
            return CadenceDecision(
                True,
                CompilationTrigger.EFFECTIVENESS_DROP,
                f"avg effectiveness {avg:.3f} < threshold {self._effectiveness_threshold}",
            )

        # 3. New-skill threshold.
        new_skills = self.current_skill_count(agent_id) - state.skill_count_at_last_compile
        if new_skills >= self._skill_count_threshold:
            return CadenceDecision(
                True,
                CompilationTrigger.SKILL_THRESHOLD,
                f"{new_skills} new skills >= threshold {self._skill_count_threshold}",
            )

        # 4. Weekly cron (lazy timestamp check).
        if state.last_compile_at is None:
            return CadenceDecision(
                True, CompilationTrigger.WEEKLY_CRON, "never compiled; initial cron compile due"
            )
        elapsed = now - state.last_compile_at
        if elapsed >= self._cron_interval:
            return CadenceDecision(
                True,
                CompilationTrigger.WEEKLY_CRON,
                f"{elapsed.days}d since last compile >= {self._cron_interval_days}d",
            )

        return CadenceDecision(
            False,
            None,
            (
                f"no trigger (avg_effectiveness={avg}, new_skills={new_skills}, "
                f"elapsed_days={elapsed.days})"
            ),
        )

    # -------------------------------------------------------------------- lock

    async def try_acquire(self, agent_id: str) -> bool:
        """Non-blocking per-agent compile lock. ``False`` → already in flight.

        Within one event loop there is no ``await`` between the ``locked()``
        check and ``acquire()``, so the check-then-acquire is race-free.
        """
        lock = self._locks.setdefault(agent_id, asyncio.Lock())
        if lock.locked():
            _LOG.info(
                "compilation_cadence.lock_skipped agent_id=%s reason=another_compilation_in_flight",
                agent_id,
            )
            return False
        await lock.acquire()
        _LOG.info("compilation_cadence.lock_acquired agent_id=%s", agent_id)
        return True

    def release(self, agent_id: str) -> None:
        """Release the per-agent compile lock (no-op if not held)."""
        lock = self._locks.get(agent_id)
        if lock is not None and lock.locked():
            lock.release()
            _LOG.info("compilation_cadence.lock_released agent_id=%s", agent_id)


__all__ = [
    "DEFAULT_CRON_INTERVAL_DAYS",
    "DEFAULT_EFFECTIVENESS_THRESHOLD",
    "DEFAULT_SKILL_COUNT_THRESHOLD",
    "CadenceDecision",
    "CadenceState",
    "CompilationCadenceController",
    "CompilationTrigger",
]
