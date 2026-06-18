"""Skill-trace persistence (T2) — substrate for the Hermes DSPy loop (ADR-021).

GEPA/DSPy skill compilation needs a **multi-example** trainset to produce any optimization
signal. Today deployed skills carry only a provenance *hash*, not their originating trace,
so every compilation assembles a 1-example trainset (no signal — see the A.4 v0.2.5
quality-delta report). T2 fixes that by persisting each deployed skill's **originating
trace** so trainset assembly can pull N scored ``(skill_id, trace)`` examples.

**Substrate shape (ADR-021):** a thin typed store over the existing ``SemanticStore``
``entities`` table — ``entity_type="skill_trace"``, keyed ``(agent_id, skill_id)``. No new
table, no alembic migration; the substrate touch is this additive module + the entity-type
convention. Tenant-scoped by construction (every read/write pins ``customer_id``, ADR-007).

This module is **infrastructure only** — it does not flip ``NEXUS_DSPY_PRODUCTION`` or
compile anything. The meta-harness wires record-at-deploy + trainset-from-store on top.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_ENTITY_TYPE = "skill_trace"


@dataclass(frozen=True, slots=True)
class SkillTraceExample:
    """One persisted (skill, originating-trace) example for trainset assembly."""

    skill_id: str
    agent_id: str
    category: str
    trace: str
    effectiveness_score: float | None
    audit_hashes: tuple[str, ...] = ()


class SkillTraceStore:
    """Tenant-scoped persistence of skill originating-traces (T2), over the SemanticStore.

    Opt-in / inert when no store is injected (mirrors the kg_writer-base contract) — so the
    meta-harness deploy path is a no-op offline and stays byte-identical.
    """

    def __init__(self, semantic_store: SemanticStore | None, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    @property
    def enabled(self) -> bool:
        """True when a store is injected (writes/reads are live); False = inert no-op."""
        return self._semantic_store is not None

    async def record_trace(
        self,
        *,
        agent_id: str,
        skill_id: str,
        category: str,
        trace: str,
        audit_hashes: tuple[str, ...] = (),
        effectiveness_score: float | None = None,
    ) -> str | None:
        """Persist a deployed skill's originating trace. Idempotent on (agent_id, skill_id).

        Returns the entity_id, or ``None`` when inert (no store) or the trace is empty.
        """
        if self._semantic_store is None or not skill_id or not trace:
            return None
        return await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type=_ENTITY_TYPE,
            external_id=f"{agent_id}:{skill_id}",
            properties={
                "agent_id": agent_id,
                "skill_id": skill_id,
                "category": category,
                "trace": trace,
                "audit_hashes": list(audit_hashes),
                "effectiveness_score": effectiveness_score,
            },
        )

    async def list_traces(
        self, *, agent_id: str, category: str | None = None
    ) -> list[SkillTraceExample]:
        """Return all persisted traces for an agent (optionally filtered by skill category).

        The N-example source for DSPy/GEPA trainset assembly. Empty when inert.
        """
        if self._semantic_store is None:
            return []
        rows = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=_ENTITY_TYPE
        )
        out: list[SkillTraceExample] = []
        for row in rows:
            props: dict[str, Any] = row.properties or {}
            if props.get("agent_id") != agent_id:
                continue
            if category is not None and props.get("category") != category:
                continue
            trace = str(props.get("trace", ""))
            if not trace:
                continue
            score = props.get("effectiveness_score")
            raw_hashes = props.get("audit_hashes") or []
            out.append(
                SkillTraceExample(
                    skill_id=str(props.get("skill_id", "")),
                    agent_id=agent_id,
                    category=str(props.get("category", "")),
                    trace=trace,
                    effectiveness_score=float(score) if isinstance(score, int | float) else None,
                    audit_hashes=tuple(str(h) for h in raw_hashes),
                )
            )
        return out


__all__ = ["SkillTraceExample", "SkillTraceStore"]
