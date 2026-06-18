"""DSPy-compiled Stage 7 SKILL_CREATE composer — v0.2.5 Task 5 (LOW-RISK).

The DSPy half of the brainstorm-Q3 **parallel composer**: a DSPy-compiled
SKILL_CREATE path that runs *alongside* the existing single-LLM-call composer.
Per Q3, an eval-gate adjudicates the winner per skill creation — that
adjudication is **Task 6** (here it is a documented stub that keeps the legacy
candidate). Compilation *cadence* (when to compile) is **Task 7**; this module
only provides the composer machinery a cadence/driver invokes.

Integrates:
- `charter.dspy_compiler.DSPyCompiler` (Task 2 substrate — the LM↔GEPA seam)
- `meta_harness.gepa_adapter.GEPAMetricAdapter` (Task 4 — GEPA ``metric=``)
- the legacy single-LLM-call composer's output (passed in; never modified here)

**Q5-a mechanism correction (drift event — see PR / verification record).**
The brainstorm Q5-a said the adapter returns ``None`` to make GEPA "skip"
None/zero-confidence skills. Offline verification (2026-06-05) found GEPA does
**not** tolerate a ``None`` metric return — it raises
``TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'``. Q5-a's
*intent* ("exclude these skills from compilation training data") is preserved by
**pre-filtering the trainset** (``build_compilation_trainset``) so GEPA's metric
only ever sees scorable skills. The adapter's ``None`` return remains as a
defensive safety net but is unreachable in normal operation.

**Optional-dependency contract (Task 1).** No top-level ``import dspy`` — every
DSPy import is gated inside the function that needs it, so this module imports
cleanly without the ``[dspy]`` extra.

**Leaf-module discipline.** Imports only `charter.{audit,llm,dspy_compiler}`,
`shared.skill_telemetry`, and `meta_harness.{gepa_adapter,effectiveness_store}`
— never `skill_lifecycle` / `skill_writer` / `skill_eval_gate` / `skill_approval`.
"""

from __future__ import annotations

import importlib
import logging
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from charter.memory.skill_trace import SkillTraceStore

from charter.audit import AuditLog
from charter.dspy_compiler import DEFAULT_GEPA_AUTO, DSPyCompiler
from charter.llm import LLMProvider
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.effectiveness_store import get_effectiveness_score
from meta_harness.gepa_adapter import GEPAMetricAdapter

_LOG = logging.getLogger(__name__)

# DSPy field name the compiled program emits — the agentskills.io SKILL.md body.
_SKILL_MD_FIELD = "skill_md"


def _require_dspy() -> Any:
    """Import ``dspy`` or raise a clear, actionable error (gated; see module doc).

    Uses ``importlib`` rather than a literal ``import dspy`` so the package's
    optional-dependency guard (Task 1: no ``import dspy`` anywhere in meta_harness
    src) holds while the import stays lazy.
    """
    try:
        return importlib.import_module("dspy")
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ImportError(
            "DSPy is not installed. Install the optional skill-optimization extra:\n"
            "    uv pip install -e packages/agents/meta-harness[dspy]"
        ) from exc


def _build_skill_creator_module() -> Any:
    """Build the DSPy SKILL_CREATE module.

    The ``Signature`` + ``Module`` subclasses are defined *inside* this function
    so the ``dspy`` base classes are referenced only when the extra is present.
    """
    dspy = _require_dspy()

    class SkillExtractor(dspy.Signature):  # type: ignore[misc, name-defined]
        """Extract a reusable, agentskills.io-formatted skill from a successful
        agent run trace."""

        trace: str = dspy.InputField(desc="Audit trace from a successful agent run")
        agent_id: str = dspy.InputField(desc="The agent the skill is for")
        skill_md: str = dspy.OutputField(desc="agentskills.io-formatted SKILL.md content")

    class DSPySkillCreator(dspy.Module):  # type: ignore[misc, name-defined]
        """Chain-of-thought wrapper around ``SkillExtractor``."""

        def __init__(self) -> None:
            super().__init__()
            self.extract = dspy.ChainOfThought(SkillExtractor)

        def forward(self, trace: str, agent_id: str) -> Any:
            return self.extract(trace=trace, agent_id=agent_id)

    return DSPySkillCreator()


@dataclass(frozen=True)
class TrainsetBuildResult:
    """Outcome of pre-filtering skills into a GEPA-safe trainset (Q5-a fix)."""

    trainset: list[Any]  # list[dspy.Example] — typed Any to avoid a hard dspy dep
    included_skill_ids: tuple[str, ...]
    skipped_skill_ids: tuple[str, ...]  # None / zero-confidence — excluded upfront


def build_compilation_trainset(
    examples: list[tuple[str, str]],
    agent_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> TrainsetBuildResult:
    """Build a GEPA-safe trainset, pre-filtering out un-scorable skills (Q5-a fix).

    ``examples`` is a list of ``(skill_id, trace)`` pairs. A skill is **included**
    only when ``get_effectiveness_score`` returns a usable score (not ``None``,
    ``confidence > 0``, ``global_score is not None``) — i.e. exactly the skills
    the GEPA metric adapter would *not* skip. Everything else is excluded from
    the trainset so the adapter never returns ``None`` to GEPA (which crashes).
    """
    dspy = _require_dspy()
    workspace_root = Path(workspace_root)
    trainset: list[Any] = []
    included: list[str] = []
    skipped: list[str] = []
    for skill_id, trace in examples:
        score = get_effectiveness_score(
            skill_id, agent_id, workspace_root=workspace_root, tenant_id=tenant_id
        )
        if score is None or score.confidence == 0.0 or score.global_score is None:
            skipped.append(skill_id)
            continue
        example = dspy.Example(trace=trace, agent_id=agent_id, skill_id=skill_id).with_inputs(
            "trace", "agent_id"
        )
        trainset.append(example)
        included.append(skill_id)
    return TrainsetBuildResult(
        trainset=trainset,
        included_skill_ids=tuple(included),
        skipped_skill_ids=tuple(skipped),
    )


async def build_compilation_trainset_from_store(
    store: SkillTraceStore,
    agent_id: str,
    category: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
    current_example: tuple[str, str] | None = None,
) -> TrainsetBuildResult:
    """Assemble a **multi-example** trainset from persisted skill traces (T2 / Phase 4a-2).

    Pulls every persisted ``(skill_id, trace)`` for ``agent_id`` + ``category`` from the
    ``SkillTraceStore`` (ADR-021), optionally appends the current trigger's example, dedups
    by ``skill_id`` (newest trace wins), then runs the **same Q5-a effectiveness pre-filter**
    as :func:`build_compilation_trainset`. This is what un-starves GEPA — N scored examples
    instead of the single current-trigger skill (which the pre-filter always dropped).
    """
    by_skill: dict[str, str] = {}
    for example in await store.list_traces(agent_id=agent_id, category=category):
        if example.trace:
            by_skill[example.skill_id] = example.trace
    if current_example is not None:
        skill_id, trace = current_example
        if trace:
            by_skill[skill_id] = trace
    return build_compilation_trainset(
        list(by_skill.items()), agent_id, workspace_root=workspace_root, tenant_id=tenant_id
    )


def create_compiled_composer(
    provider: LLMProvider,
    *,
    agent_id: str,
    model_pin: str,
    workspace_root: Path,
    audit_log: AuditLog,
    trainset: list[Any],
    tenant_id: str = "default",
    seed: int | None = None,
    auto: str | None = DEFAULT_GEPA_AUTO,
    max_metric_calls: int | None = None,
) -> Any:
    """Compile a DSPy SKILL_CREATE composer for ``agent_id`` (returns the compiled
    ``dspy.Module``).

    Uses ``DSPyCompiler`` (Task 2) bound to ``provider`` and ``GEPAMetricAdapter``
    (Task 4) as the metric. ``trainset`` must already be pre-filtered via
    ``build_compilation_trainset`` (Q5-a) so the adapter never returns ``None``.
    """
    compiler = DSPyCompiler(provider, model_pin=model_pin, seed=seed)
    metric = GEPAMetricAdapter(
        agent_id,
        workspace_root=Path(workspace_root),
        audit_log=audit_log,
        tenant_id=tenant_id,
    )
    module = _build_skill_creator_module()
    return compiler.compile(
        module,
        trainset=trainset,
        metric=metric,
        optimizer="gepa",
        auto=auto,
        max_metric_calls=max_metric_calls,
    )


@dataclass(frozen=True)
class ParallelSkillResult:
    """Outcome of one parallel SKILL_CREATE (legacy + DSPy).

    Carries both candidate outputs; the **winner is decided by the orchestrator**
    (``skill_lifecycle``), which eval-gates the DSPy candidate and calls
    ``adjudicate_pass_rates`` (Task 6) — the leaf does not eval-gate or import the
    eval-gate (leaf-module discipline).
    """

    legacy_skill_md: str
    dspy_skill_md: str | None
    dspy_error: str | None  # populated when the DSPy path failed (CF #2)


def adjudicate_pass_rates(
    legacy_pass_rate: float,
    dspy_pass_rate: float,
    legacy_skill_md: str,
    dspy_skill_md: str,
) -> tuple[str, dict[str, Any]]:
    """Pure pass-rate comparator (Task 6, brainstorm Q3 winner-selection).

    The DSPy candidate wins only if it **strictly beats** the legacy candidate's
    eval-gate ``candidate_pass_rate``; a tie goes to legacy (Q3 safety default —
    DSPy must demonstrably beat the baseline path to be persisted).

    Pure function — the orchestrator supplies both pass-rates (from the legacy
    candidate's existing eval-gate result + a fresh eval-gate run on the DSPy
    candidate). No eval-gate calls here, so the leaf imports no eval-gate.

    Returns ``(winning_skill_md, metadata)`` where metadata carries both
    pass-rates, the winner identifier, and the delta (for Q8 quality-delta
    plumbing read by Task 12).
    """
    delta = dspy_pass_rate - legacy_pass_rate
    if dspy_pass_rate > legacy_pass_rate:
        winner, winning_skill_md = "dspy", dspy_skill_md
    else:
        winner, winning_skill_md = "legacy", legacy_skill_md
    return winning_skill_md, {
        "winner": winner,
        "legacy_pass_rate": legacy_pass_rate,
        "dspy_pass_rate": dspy_pass_rate,
        "delta": delta,
    }


def run_parallel_skill_create(
    *,
    trace: str,
    agent_id: str,
    model_pin: str,
    provider: LLMProvider,
    workspace_root: Path,
    audit_log: AuditLog,
    legacy_skill_md: str,
    trainset: list[Any],
    tenant_id: str = "default",
    seed: int | None = None,
) -> ParallelSkillResult:
    """Run the DSPy composer alongside the (already-produced) legacy output.

    The legacy ``skill_md`` is produced by the caller's existing single-LLM-call
    composer and passed in unchanged. The DSPy path is **best-effort**: any
    failure (compilation error, missing extra, provider error) is caught,
    emitted to the audit chain as ``meta_harness.skill.effectiveness_error``
    (CF #2 — no new audit constant per Q7), and the legacy candidate proceeds.
    """
    dspy_skill_md: str | None = None
    dspy_error: str | None = None
    try:
        compiled = create_compiled_composer(
            provider,
            agent_id=agent_id,
            model_pin=model_pin,
            workspace_root=Path(workspace_root),
            audit_log=audit_log,
            trainset=trainset,
            tenant_id=tenant_id,
            seed=seed,
        )
        prediction = compiled(trace=trace, agent_id=agent_id)
        dspy_skill_md = getattr(prediction, _SKILL_MD_FIELD, None)
        if not dspy_skill_md:
            dspy_error = "compiled program produced no skill_md output"
    except Exception as exc:  # CF #2: never let the DSPy path break Stage 7
        dspy_error = str(exc)
        _LOG.warning(
            "DSPy SKILL_CREATE path failed for agent_id=%s; legacy proceeds: %s",
            agent_id,
            exc,
        )
        audit_log.append(
            ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
            {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "error_type": "dspy_skill_create_failed",
                "exception_message": str(exc),
                "stack_trace": traceback.format_exc(),
                "fallback": "legacy_path",
            },
        )

    # Winner-selection is the orchestrator's job (it has the eval-gate + legacy
    # eval result); the leaf returns both candidates for adjudication.
    return ParallelSkillResult(
        legacy_skill_md=legacy_skill_md,
        dspy_skill_md=dspy_skill_md,
        dspy_error=dspy_error,
    )


__all__ = [
    "ParallelSkillResult",
    "TrainsetBuildResult",
    "adjudicate_pass_rates",
    "build_compilation_trainset",
    "create_compiled_composer",
    "run_parallel_skill_create",
]
