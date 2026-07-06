"""AttackPathWriter — persists ranked AttackPath objects as ATTACK_PATH graph nodes (P1).

Each ranked (AttackPath, expected_loss, blast_radius) tuple is upserted as a single
``ATTACK_PATH`` node whose identity key is:

    ``"attackpath:" + sha256(path_type | sorted(entities))[:16]``

This is the same grouping key the ranker uses internally (``attack_paths.py:245``), so
"the same path" collapses across scans.  ``CONTRIBUTES_TO`` edges are written from every
entity id in ``path.entities`` to the node.

Cross-scan dedup contract (ADR-022):
- ``first_seen`` is **set-once**: the writer reads the existing node (via a preliminary
  ``upsert_node`` with no props → get entity_id → ``get_entity``) to check whether
  ``first_seen`` was already stored; if so it is preserved; if not it is stamped to
  ``now``.
- ``last_seen`` is overwritten on every scan (always ``now``).
- ``CONTRIBUTES_TO`` edges are idempotent (DB UNIQUE index first-wins + within-run
  dedup set in the base).

Inert when ``semantic_store is None`` (base contract, Q5 operating rule).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from meta_harness.attack_paths import AttackPath

_log = logging.getLogger(__name__)


def attack_path_external_id(path: AttackPath) -> str:
    """Deterministic, stable key for a path — collapses same-path across runs.

    Shared between the graph writer (P1) and the OCSF builder (P2) so that
    ``finding_info.uid`` in the emitted OCSF 2005 finding equals the
    ``external_id`` of the persisted ``ATTACK_PATH`` node, enabling SIEM dedup.
    """
    raw = path.path_type + "|" + "|".join(sorted(path.entities))
    return "attackpath:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


# Backward-compatible private alias (used by existing tests + internal calls).
_attack_path_external_id = attack_path_external_id


class AttackPathWriter(KnowledgeGraphWriterBase):
    """Writes each ranked AttackPath as an ATTACK_PATH node + CONTRIBUTES_TO edges."""

    async def persist(
        self,
        ranked: Sequence[tuple[AttackPath, float, int]],
        *,
        now: datetime,
    ) -> None:
        """Upsert every ranked path as a durable ATTACK_PATH node.

        Args:
            ranked: Sequence of (AttackPath, expected_loss, blast_radius) tuples,
                    as produced by ``rank_by_expected_loss``.
            now:    Caller-supplied timestamp (scan boundary). ``first_seen`` is
                    set to this value only when the node is new; ``last_seen``
                    is always overwritten with this value.

        Returns:
            None currently; will return ``list[dict]`` (OCSF findings) in Task 2
            (P2) once ``build_incident_finding`` is wired in.
        """
        if self._semantic_store is None:
            return

        for path, expected_loss, blast in ranked:
            try:
                await self._persist_one(path, expected_loss, blast, now=now)
            except Exception:
                _log.warning(
                    "AttackPathWriter: failed to persist path path_type=%r key=%r — skipping",
                    path.path_type,
                    _attack_path_external_id(path),
                    exc_info=True,
                )

    async def _persist_one(
        self,
        path: AttackPath,
        expected_loss: float,
        blast: int,
        *,
        now: datetime,
    ) -> None:
        # _persist_one is only called from persist() after the store-None guard.
        if self._semantic_store is None:  # pragma: no cover — guard already in persist()
            return

        external_id = _attack_path_external_id(path)

        # Step 1: upsert with empty props to resolve/create the entity_id without
        # clobbering first_seen.
        node_id = await self.upsert_node(NodeCategory.ATTACK_PATH, external_id, {})
        if not node_id:
            return

        # Step 2: read the stored node to check whether first_seen was already set.
        existing = await self._semantic_store.get_entity(
            tenant_id=self._customer_id,
            entity_id=node_id,
        )
        stored_first_seen: str | None = (
            existing.properties.get("first_seen") if existing is not None else None
        )

        # Step 3: build the full props, preserving first_seen when already stored.
        props: dict[str, Any] = {
            "path_type": path.path_type,
            "severity": path.severity,
            "expected_loss": expected_loss,
            "blast_radius": blast,
            "title": path.title,
            "evidence": list(path.evidence),
            "sink_id": path.sink_id,
            "count": path.count,
            "kev": path.kev,
            "epss": path.epss,
            "entities": list(path.entities),
            "first_seen": stored_first_seen if stored_first_seen is not None else now.isoformat(),
            "last_seen": now.isoformat(),
        }

        # Step 4: upsert with full props (merges; first_seen survives because it was
        # already in the store OR we're writing it for the first time).
        node_id = await self.upsert_node(NodeCategory.ATTACK_PATH, external_id, props)
        if not node_id:
            return

        # Step 5: CONTRIBUTES_TO edges from each entity in the path.
        for entity in path.entities:
            await self.add_edge(entity, node_id, EdgeType.CONTRIBUTES_TO, {})

        # Step 6: PART_OF_PATH edge to the sink node (data classification reached).
        # Enables "what paths reach this data?" graph traversal (sink_id property alone
        # cannot answer this without a graph edge).
        if path.sink_id:
            await self.add_edge(node_id, path.sink_id, EdgeType.PART_OF_PATH, {})


__all__ = ["AttackPathWriter", "attack_path_external_id"]
