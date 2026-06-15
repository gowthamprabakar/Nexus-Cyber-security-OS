"""Skill-candidate persistence helper — Hermes Phase 1 (Track C C-2 PR1).

A thin, dependency-clean helper the LLM-narration trio (D.13 / D.7 / D.12) calls
to PROPOSE a skill candidate by upserting it into the cross-session SemanticStore
(C2-C: the trio proposes; the meta-harness eval-gate + C-1 adjudication remain the
SOLE deploy authority — this helper never deploys).

**Canary discipline.** ``nexus_runtime`` is the ``dependencies = []`` package, so
the ``SemanticStore`` it persists into is **injected by the caller** and imported
ONLY under ``TYPE_CHECKING``. At runtime no ``charter`` import happens here; the
caller (which already holds a live ``SemanticStore`` from its own charter context)
passes the instance in. This keeps the helper a pure orchestration shim.

**Scope note for review (deviation surfaced, not assumed).** The C2-A decision
named "SemanticStore + LLMProvider as params." LLM *composition* of the candidate
body is the trio's own concern via its ``providers/`` (``charter.llm``); by the time
this helper is called the candidate is already composed. So this persistence helper
takes only the injected ``SemanticStore`` — adding an unused ``LLMProvider`` param
would be a placeholder, which the overnight/PR discipline forbids. If the operator
prefers the literal two-param signature (e.g. to compose-and-store in one call),
say so on this PR and I'll fold composition in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

#: SemanticStore entity_type for proposed (not-yet-adjudicated) skill candidates.
SKILL_CANDIDATE_ENTITY_TYPE = "skill_candidate"


async def upsert_skill_candidate(
    store: SemanticStore,
    *,
    tenant_id: str,
    skill_id: str,
    properties: dict[str, Any] | None = None,
) -> str:
    """Idempotently persist a proposed skill candidate to the SemanticStore.

    Keyed by ``(tenant_id, "skill_candidate", skill_id)`` so re-proposing the
    same candidate merges rather than duplicates. Returns the entity_id (ULID).

    The ``store`` is injected by the caller (the trio's charter context) — this
    helper never constructs one, preserving ``nexus_runtime``'s empty deps.
    """
    return await store.upsert_entity(
        tenant_id=tenant_id,
        entity_type=SKILL_CANDIDATE_ENTITY_TYPE,
        external_id=skill_id,
        properties=properties,
    )


__all__ = [
    "SKILL_CANDIDATE_ENTITY_TYPE",
    "upsert_skill_candidate",
]
