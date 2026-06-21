"""Instantiate the TOXIC_COMBINATION node + build its emittable hypothesis (D.7).

Consumes the read-only ToxicCombination paths from meta-harness `kg_query` and
turns them into (a) a graph decoration — the TOXIC_COMBINATION node the catalogue
defines but nothing has instantiated until now — and (b) an OCSF-2005 Hypothesis
with evidence refs to the contributing findings.
"""

from __future__ import annotations

import hashlib

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase
from meta_harness.kg_query import ToxicCombination

from investigation.schemas import Hypothesis


def _combo_external_id(combo: ToxicCombination) -> str:
    raw = f"{combo.principal_id}|{combo.resource_id}|{combo.data_classification_id}"
    return "toxic:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


class ToxicCombinationWriter(KnowledgeGraphWriterBase):
    """Writes the TOXIC_COMBINATION node + CONTRIBUTES_TO edges from contributors."""

    async def record(self, combo: ToxicCombination) -> str | None:
        node_id = await self.upsert_node(
            NodeCategory.TOXIC_COMBINATION,
            _combo_external_id(combo),
            {"kind": "public-data-exposure"},
        )
        for contributor in (
            combo.principal_id,
            combo.resource_id,
            combo.data_classification_id,
        ):
            await self.add_edge(contributor, node_id or "", EdgeType.CONTRIBUTES_TO, {})
        return node_id


def to_hypothesis(combo: ToxicCombination, *, evidence_refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=_combo_external_id(combo),
        statement=(
            "Public bucket holds sensitive data and is reachable by an "
            "over-permissioned principal (public-data-exposure attack path)."
        ),
        confidence=1.0,  # graph-evidenced (all three legs present), not LLM-inferred
        evidence_refs=evidence_refs,
    )


__all__ = ["ToxicCombinationWriter", "to_hypothesis"]
