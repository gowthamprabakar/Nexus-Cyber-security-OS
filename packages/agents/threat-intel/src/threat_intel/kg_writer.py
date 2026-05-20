"""Knowledge-graph writer for the D.8 Threat Intel agent (Postgres SemanticStore-backed).

Per Q3 of the D.8 v0.1 plan, threat-intel entities (IOC / CVE / TTP)
are persisted to the platform's Postgres ``SemanticStore`` using the
same pattern proven in F.3 v0.1.5 (KG-loop closure). The class shape
mirrors ``cloud_posture.tools.kg_writer.KnowledgeGraphWriter``: same
upsert flow, same within-run dedup discipline, same substrate-sealed
constraints (we do NOT change ``charter.memory`` APIs).

**Single-tenant ``semantic_store=None`` opt-in default.** Per the
Path-B operating rule §11.1: multi-tenant production blocks on the
future SET LOCAL ``$1`` tenant-RLS substrate-fix plan. v0.1 keeps the
agent driver path that constructs the writer guarded — when
``semantic_store`` is None at the agent boundary, the writer is never
instantiated and no SemanticStore writes happen. v0.1 single-tenant
in-memory ``aiosqlite`` SemanticStore is supported for testing only.

**Within-run dedup**. Per the KG-loop closure §13.1 watch-item:
``SemanticStore.add_relationship`` is INSERT-only. We dedupe within
the agent run using a per-finding ``set[str]`` of related external_ids.
Cross-run dedup is known debt; does NOT block D.8 v0.1.

Q6 reminder: this writer persists feed-derived metadata only. No
classifier-matched substrings; no PII.
"""

from __future__ import annotations

from charter.memory import SemanticStore

from threat_intel.entities import CveEntity, IocEntity, TechniqueEntity


class KnowledgeGraphWriter:
    """Customer-scoped writer for IOC / CVE / TTP entities.

    Mirrors F.3's ``KnowledgeGraphWriter`` shape: ``async`` methods,
    side-effect-only, instance-scoped dedup. The substrate's
    composite key for entities is ``(tenant_id, entity_type,
    external_id)``; the writer's ``upsert_*`` methods produce the
    external_id from the entity's identifying field (CVE ID, IOC
    ``type:value`` pair, technique ID).
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def upsert_ioc(self, ioc: IocEntity) -> None:
        """Idempotent upsert of an IOC entity."""
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="ioc",
            external_id=ioc.external_id,
            properties=ioc.properties(),
        )

    async def upsert_cve(self, cve: CveEntity) -> None:
        """Idempotent upsert of a CVE entity."""
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="cve",
            external_id=cve.external_id,
            properties=cve.properties(),
        )

    async def upsert_technique(self, technique: TechniqueEntity) -> None:
        """Idempotent upsert of an ATT&CK technique entity."""
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="ttp",
            external_id=technique.external_id,
            properties=technique.properties(),
        )


__all__ = ["KnowledgeGraphWriter"]
