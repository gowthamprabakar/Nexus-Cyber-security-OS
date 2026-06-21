"""Instantiate the TOXIC_COMBINATION node + build its emittable hypothesis (D.7).

Consumes the read-only ToxicCombination paths from meta-harness `kg_query` and
turns them into (a) a graph decoration — the TOXIC_COMBINATION node the catalogue
defines but nothing has instantiated until now — and (b) an OCSF-2005 Hypothesis
with evidence refs to the contributing findings.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase
from meta_harness.kg_query import KgQuery, ToxicCombination

from investigation.schemas import Hypothesis

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

    from investigation.tools.related_findings import RelatedFinding

# OCSF wire value of identity's FindingType.OVERPRIVILEGE. D.7 consumes findings by
# their wire shape, NOT by importing the producer's enum (avoids a cross-package dep).
_OVERPRIVILEGE = "overprivilege"


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


async def detect_toxic_combination_hypotheses(
    *,
    semantic_store: SemanticStore,
    customer_id: str,
    related_findings: Sequence[RelatedFinding],
) -> tuple[Hypothesis, ...]:
    """Turn identity overprivilege findings into toxic-combination hypotheses.

    For each over-permissioned principal, resolve it to its graph node, run the
    public-data-exposure detector, write the TOXIC_COMBINATION node, and build a
    Hypothesis citing the identity finding's uid (a `finding:<uid>` ref D.7's
    Stage 4 validator resolves). Empty tuple when nothing qualifies.
    """
    ref_by_principal: dict[str, str] = {}
    for rf in related_findings:
        if rf.class_uid != 2004:
            continue
        info = rf.payload.get("finding_info") or {}
        types = info.get("types") or []
        if _OVERPRIVILEGE not in types:
            continue
        finding_uid = str(info.get("uid") or "")
        if not finding_uid:
            continue
        for principal in rf.payload.get("affected_principals", []):
            arn = str(principal.get("uid", ""))
            if not arn:
                continue
            entity_id = await semantic_store.upsert_entity(
                tenant_id=customer_id,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=arn,
                properties={},
            )
            ref_by_principal.setdefault(entity_id, f"finding:{finding_uid}")

    if not ref_by_principal:
        return ()

    hits = await KgQuery(semantic_store, customer_id).find_public_data_exposure(
        over_permissioned_principal_ids=list(ref_by_principal),
    )
    writer = ToxicCombinationWriter(semantic_store, customer_id)
    hypotheses: list[Hypothesis] = []
    for combo in hits:
        ref = ref_by_principal.get(combo.principal_id)
        if ref is None:
            continue
        await writer.record(combo)
        hypotheses.append(to_hypothesis(combo, evidence_refs=(ref,)))
    return tuple(hypotheses)


__all__ = ["ToxicCombinationWriter", "detect_toxic_combination_hypotheses", "to_hypothesis"]
