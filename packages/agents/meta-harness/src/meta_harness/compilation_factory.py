"""DSPy candidate factory — v0.2.5 Task 7b (brings the pipeline production-live).

Bridges the pieces shipped in Tasks 2/4/5/6/7a into the
``dspy_candidate_factory`` that ``skill_lifecycle`` injects (Task 6):

    cadence (7a) → per-agent lock (7a) → trainset (5) → compile (2+4+5) →
    materialise a ``SkillCandidate`` at the legacy canonical shadow path →
    return it for adjudication (6).

The factory writes the DSPy ``SKILL.md`` to the **legacy candidate's canonical
shadow path** (overwriting it) so the eval-gate's per-agent overlay measures the
DSPy candidate cleanly (apples-to-apples vs the legacy run). The adjudicator
(Task 6, R1 amendment) restores the legacy ``SKILL.md`` if legacy wins.

**CF #2** at every failure point: cadence-no / lock-unavailable / empty-trainset
/ compile-error → return ``None`` → the legacy candidate proceeds alone.

**Rollout (default-OFF):** :func:`make_default_dspy_factory` constructs the
factory only when ``NEXUS_DSPY_PRODUCTION=1``; otherwise it returns ``None`` and
``skill_lifecycle`` runs legacy-only (unchanged behaviour). Production rollout is
a deliberate flag flip after the Task 14 Anthropic switch-validation.

**KNOWN LIMITATION (T2) — trainset is empty in production today.** The factory
can only assemble a trainset from the *current trigger's* skill, which is brand
new and therefore unscored — and the Q5-a pre-filter (correctly) drops unscored
skills, so the trainset comes back empty and the factory no-ops. Multi-example
trainsets need *originating traces persisted with deployed skills*, which does
not exist yet (deployed ``Skill``s carry provenance hashes, not raw traces). The
cadence / lock / factory / materialisation / adjudication / persistence
machinery is production-ready; only trainset *diversity* is constrained. The live
pipeline test exercises real compilation by seeding a scored skill. Persisting
traces is a post-v0.2.5 follow-up (v0.3 candidate).
"""

from __future__ import annotations

import logging
import os
import traceback
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from charter.audit import AuditLog
from charter.llm import LLMProvider
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.compilation_cadence import CompilationCadenceController
from meta_harness.dspy_skill_creator import (
    build_compilation_trainset,
    create_compiled_composer,
)
from meta_harness.schemas import (
    Scorecard,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_format import parse_skill_md_content, write_skill_md
from meta_harness.skill_triggers import SkillTrigger
from meta_harness.skill_writer import compose_skill_prompt

_LOG = logging.getLogger(__name__)

_SKILL_MD_FIELD = "skill_md"
ENV_PRODUCTION_FLAG = "NEXUS_DSPY_PRODUCTION"

# Type of the factory ``skill_lifecycle`` injects (extended in 7b to carry the
# trigger, which the DSPy composer needs for its trace inputs).
DSPyCandidateFactory = Callable[
    [Scorecard, SkillCandidate, SkillTrigger], Awaitable[SkillCandidate | None]
]


def _materialize_dspy_candidate(
    dspy_skill_md: str,
    *,
    legacy_candidate: SkillCandidate,
    agent_id: str,
    now: datetime,
) -> SkillCandidate:
    """Turn DSPy's ``skill_md`` into a ``SkillCandidate`` pinned to the legacy
    candidate's identity (skill_id + canonical shadow path).

    Pinning the path guarantees a clean overwrite of the legacy ``SKILL.md`` so
    the eval-gate's per-agent overlay measures the DSPy content at the same
    position the legacy run used (apples-to-apples). Content = DSPy; identity =
    legacy.
    """
    parsed = parse_skill_md_content(dspy_skill_md, source="<dspy:skill_creator>")
    skill = parsed.model_copy(
        update={
            "target_agent": agent_id,
            "deployment_status": SkillDeploymentStatus.CANDIDATE,
            "eval_gate_status": SkillEvalGateStatus.NOT_RUN,
            "created_by": legacy_candidate.skill.created_by,
            "provenance": legacy_candidate.skill.provenance,
        }
    )
    candidate = SkillCandidate(
        skill_id=legacy_candidate.skill_id,
        skill=skill,
        shadow_path=legacy_candidate.shadow_path,
        tool_sequence_hash=legacy_candidate.tool_sequence_hash,
        emitted_at=now,
    )
    write_skill_md(skill, Path(legacy_candidate.shadow_path))
    return candidate


def make_dspy_candidate_factory(
    provider: LLMProvider,
    *,
    cadence_controller: CompilationCadenceController,
    model_pin: str,
    workspace_root: Path,
    audit_log: AuditLog,
    tenant_id: str = "default",
    seed: int | None = None,
) -> DSPyCandidateFactory:
    """Build the ``dspy_candidate_factory`` ``skill_lifecycle`` injects (Task 6).

    The returned coroutine: evaluates cadence (7a) → acquires the per-agent lock
    → builds the trainset (5) → compiles (2+4+5) → materialises a
    ``SkillCandidate`` at the legacy canonical path → records the compilation in
    cadence state → returns the candidate. Any failure or no-go returns ``None``
    (CF #2 → legacy proceeds).
    """
    workspace_root = Path(workspace_root)

    async def factory(
        scorecard: Scorecard,
        legacy_candidate: SkillCandidate,
        trigger: SkillTrigger,
    ) -> SkillCandidate | None:
        agent_id = scorecard.agent_id

        decision = cadence_controller.evaluate(agent_id)
        if not decision.should_compile:
            return None  # CF #2: cadence says don't compile → legacy alone

        if not await cadence_controller.try_acquire(agent_id):
            return None  # CF #2: another compilation in flight → legacy alone

        try:
            # DSPy program input — derive the same composed view of the trigger
            # the legacy composer uses (SkillTrigger carries no raw trace).
            _system, user_prompt = compose_skill_prompt(trigger)

            # T2: assemble the trainset from the current trigger's skill. In
            # production this is empty (the new skill is unscored and the Q5-a
            # pre-filter drops unscored skills) → graceful no-op. See module
            # docstring; the live test seeds a scored skill to exercise compile.
            build = build_compilation_trainset(
                [(legacy_candidate.skill_id, user_prompt)],
                agent_id,
                workspace_root=workspace_root,
                tenant_id=tenant_id,
            )
            if not build.trainset:
                _LOG.warning(
                    "compilation_factory.empty_trainset agent_id=%s "
                    "(no scored skills with traces; DSPy no-op until trace persistence)",
                    agent_id,
                )
                return None  # CF #2: nothing to optimise against → legacy alone
            if len(build.trainset) == 1:
                _LOG.warning(
                    "compilation_factory.single_example_trainset agent_id=%s "
                    "(known v0.2.5 limitation; optimization headroom is constrained)",
                    agent_id,
                )

            compiled = create_compiled_composer(
                provider,
                agent_id=agent_id,
                model_pin=model_pin,
                workspace_root=workspace_root,
                audit_log=audit_log,
                trainset=build.trainset,
                tenant_id=tenant_id,
                seed=seed,
            )
            prediction = compiled(trace=user_prompt, agent_id=agent_id)
            dspy_skill_md = getattr(prediction, _SKILL_MD_FIELD, None)
            if not dspy_skill_md:
                _LOG.warning(
                    "compilation_factory.no_skill_md agent_id=%s (compiled program empty)",
                    agent_id,
                )
                return None

            candidate = _materialize_dspy_candidate(
                dspy_skill_md,
                legacy_candidate=legacy_candidate,
                agent_id=agent_id,
                now=datetime.now(UTC),
            )
            cadence_controller.record_compilation(agent_id)
            _LOG.info(
                "compilation_factory.candidate_produced agent_id=%s skill_id=%s trigger=%s",
                agent_id,
                candidate.skill_id,
                decision.trigger.value if decision.trigger else None,
            )
            return candidate

        except Exception as exc:  # CF #2: any compile/materialise failure → legacy
            audit_log.append(
                ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "error_type": "dspy_factory_failed",
                    "exception_message": str(exc),
                    "stack_trace": traceback.format_exc(),
                    "stage": "compilation_factory",
                    "fallback": "legacy_path",
                },
            )
            _LOG.warning("compilation_factory.failure agent_id=%s: %s", agent_id, exc)
            return None

        finally:
            cadence_controller.release(agent_id)

    return factory


def make_default_dspy_factory(
    provider: LLMProvider,
    *,
    model_pin: str,
    workspace_root: Path,
    audit_log: AuditLog,
    tenant_id: str = "default",
    seed: int | None = None,
) -> DSPyCandidateFactory | None:
    """Construct the production factory **only when ``NEXUS_DSPY_PRODUCTION=1``**.

    Default-OFF (flag unset or any value other than ``"1"``) → returns ``None``;
    the driver passes that straight to ``run_skill_lifecycle(dspy_candidate_factory=…)``,
    preserving Task 6's legacy-only default. Production rollout is a deliberate
    flag flip after the Task 14 Anthropic switch-validation.
    """
    if os.environ.get(ENV_PRODUCTION_FLAG) != "1":
        _LOG.info(
            "compilation_factory.disabled %s != '1' — Stage 7 runs legacy-only",
            ENV_PRODUCTION_FLAG,
        )
        return None
    controller = CompilationCadenceController(
        workspace_root=Path(workspace_root), tenant_id=tenant_id
    )
    _LOG.info("compilation_factory.enabled %s=1 — DSPy compilation wired", ENV_PRODUCTION_FLAG)
    return make_dspy_candidate_factory(
        provider,
        cadence_controller=controller,
        model_pin=model_pin,
        workspace_root=Path(workspace_root),
        audit_log=audit_log,
        tenant_id=tenant_id,
        seed=seed,
    )


__all__ = [
    "ENV_PRODUCTION_FLAG",
    "DSPyCandidateFactory",
    "make_default_dspy_factory",
    "make_dspy_candidate_factory",
]
