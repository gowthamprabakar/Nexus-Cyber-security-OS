"""DSPy production-flip gate — Hermes Phase 4b (Gate 3 formal flip-criterion).

``NEXUS_DSPY_PRODUCTION`` stays **default-OFF**. This module is the *honest* answer to
"when may an operator flip it on?" — it codifies the named criteria as a pure, evidence-in /
verdict-out evaluation. It **never** reads or mutates the env flag and **never** flips
anything; flipping remains a deliberate operator action. The gate exists so that decision is
made against measured evidence, not faith (the no-production-by-faith rule).

The four criteria (priority-independent — *all* must hold to authorize a flip):

* **Gate 1 — T2 trace persistence** (``t2_trace_persistence_available``). Shipped in #752/#753
  (charter ``SkillTraceStore`` + ADR-021 + the meta-harness record-at-deploy / trainset-from-
  store wiring). Without it every compilation got a 1-example trainset → GEPA produced no
  signal. Met today.
* **Gate 2 — volume cadence live** (``volume_cadence_live``). The
  :class:`~meta_harness.compilation_cadence.CompilationCadenceController` (v0.2.5 Task 7a):
  event-driven (effectiveness-drop / skill-threshold / manual) + lazy weekly cron. Met today.
* **Gate 3 — measured GEPA quality delta** (``measured_quality_delta`` over
  ``measured_delta_agent_count`` agents). The quality criterion: a real multi-example
  trainset (now possible post-T2) must produce a measured eval-gate improvement of at least
  :data:`MIN_QUALITY_DELTA` across at least :data:`MIN_DELTA_AGENTS` agents. **Not met until a
  measurement run produces that report.** This is the gate that keeps the flag off today.
* **Task-14 — Anthropic switch-validation** (``task_14_anthropic_validated``). The external
  operator validation carried since v0.2.5. Not met until the operator records it.

This is a leaf module: stdlib only. No flag, no I/O, no compilation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# Gate 3 thresholds — a flip needs a *measured* improvement, not a single lucky agent.
MIN_QUALITY_DELTA = 0.05
MIN_DELTA_AGENTS = 3


class FlipGate(Enum):
    """The four named criteria authorizing a ``NEXUS_DSPY_PRODUCTION`` flip."""

    T2_TRACE_PERSISTENCE = "t2_trace_persistence"  # Gate 1
    VOLUME_CADENCE = "volume_cadence"  # Gate 2
    QUALITY_DELTA = "quality_delta"  # Gate 3
    TASK_14_ANTHROPIC = "task_14_anthropic"


@dataclass(frozen=True, slots=True)
class FlipEvidence:
    """Measured inputs to the flip decision. Defaults reflect *today's* posture.

    Gates 1 & 2 default ``True`` (their machinery is shipped). Gate 3 defaults to *unmeasured*
    (``None`` / ``0``) and Task-14 defaults ``False`` — so the default evidence yields an
    **un-authorized** verdict. That is intentional: absence of measurement is not permission.
    """

    t2_trace_persistence_available: bool = True
    volume_cadence_live: bool = True
    measured_quality_delta: float | None = None
    measured_delta_agent_count: int = 0
    task_14_anthropic_validated: bool = False


@dataclass(frozen=True, slots=True)
class GateResult:
    """Per-criterion outcome with a human-readable explanation."""

    gate: FlipGate
    met: bool
    detail: str


@dataclass(frozen=True, slots=True)
class FlipReadiness:
    """The verdict: whether evidence authorizes a flip, plus per-gate detail."""

    authorized: bool
    gates: tuple[GateResult, ...] = field(default_factory=tuple)

    @property
    def unmet(self) -> tuple[FlipGate, ...]:
        """The gates still blocking a flip (empty iff ``authorized``)."""
        return tuple(g.gate for g in self.gates if not g.met)


def evaluate_flip_readiness(
    evidence: FlipEvidence | None = None,
    *,
    min_quality_delta: float = MIN_QUALITY_DELTA,
    min_delta_agents: int = MIN_DELTA_AGENTS,
) -> FlipReadiness:
    """Evaluate the four flip criteria against ``evidence`` (pure; no flag, no I/O).

    Returns :class:`FlipReadiness`; ``authorized`` is ``True`` only when *every* gate is met.
    Default evidence (no measured delta, Task-14 unvalidated) → not authorized.
    """
    ev = evidence or FlipEvidence()

    delta = ev.measured_quality_delta
    quality_met = (
        delta is not None
        and delta >= min_quality_delta
        and ev.measured_delta_agent_count >= min_delta_agents
    )
    if delta is None:
        quality_detail = "no measured GEPA delta yet (run a measurement compile post-T2)"
    elif not quality_met:
        quality_detail = (
            f"measured delta {delta:+.3f} over {ev.measured_delta_agent_count} agents "
            f"< required {min_quality_delta:+.3f} over {min_delta_agents}"
        )
    else:
        quality_detail = (
            f"measured delta {delta:+.3f} over {ev.measured_delta_agent_count} agents "
            f">= required {min_quality_delta:+.3f} over {min_delta_agents}"
        )

    gates = (
        GateResult(
            FlipGate.T2_TRACE_PERSISTENCE,
            ev.t2_trace_persistence_available,
            "T2 trace persistence available (#752/#753)"
            if ev.t2_trace_persistence_available
            else "T2 trace persistence missing — trainsets stay 1-example",
        ),
        GateResult(
            FlipGate.VOLUME_CADENCE,
            ev.volume_cadence_live,
            "volume cadence controller live (v0.2.5 Task 7a)"
            if ev.volume_cadence_live
            else "volume cadence not wired",
        ),
        GateResult(FlipGate.QUALITY_DELTA, quality_met, quality_detail),
        GateResult(
            FlipGate.TASK_14_ANTHROPIC,
            ev.task_14_anthropic_validated,
            "Anthropic switch-validation recorded"
            if ev.task_14_anthropic_validated
            else "Anthropic switch-validation (Task-14) not yet recorded",
        ),
    )
    return FlipReadiness(authorized=all(g.met for g in gates), gates=gates)


def render_flip_status_markdown(readiness: FlipReadiness) -> str:
    """Render an operator-facing flip-status report (the Gate-3 evidence summary).

    Capability, not authority: this only *describes* the verdict. The flip remains a manual
    operator action against this report.
    """
    verdict = "AUTHORIZED" if readiness.authorized else "NOT AUTHORIZED"
    lines = [
        "# DSPy production-flip status (`NEXUS_DSPY_PRODUCTION`)",
        "",
        f"**Verdict: flip {verdict}.** Flag remains default-OFF until an operator flips it.",
        "",
        "| Gate | Met | Detail |",
        "| --- | --- | --- |",
    ]
    for g in readiness.gates:
        mark = "✅" if g.met else "❌"
        lines.append(f"| `{g.gate.value}` | {mark} | {g.detail} |")
    if not readiness.authorized:
        blocking = ", ".join(f"`{g.value}`" for g in readiness.unmet)
        lines += ["", f"Blocking gate(s): {blocking}."]
    return "\n".join(lines) + "\n"


__all__ = [
    "MIN_DELTA_AGENTS",
    "MIN_QUALITY_DELTA",
    "FlipEvidence",
    "FlipGate",
    "FlipReadiness",
    "GateResult",
    "evaluate_flip_readiness",
    "render_flip_status_markdown",
]
