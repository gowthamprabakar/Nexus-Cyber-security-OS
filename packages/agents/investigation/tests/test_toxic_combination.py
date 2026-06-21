# packages/agents/investigation/tests/test_toxic_combination.py
import pytest
from charter.memory.graph_types import EdgeType
from fleet_testkit import in_memory_semantic_store
from investigation.toxic_combination import ToxicCombinationWriter, to_hypothesis
from meta_harness.kg_query import PathEdge, ToxicCombination


def _combo():
    return ToxicCombination(
        principal_id="P",
        resource_id="R",
        data_classification_id="D",
        path=(
            PathEdge("P", "R", EdgeType.HAS_ACCESS_TO.value),
            PathEdge("R", "D", EdgeType.EXPOSES_DATA.value),
        ),
    )


@pytest.mark.asyncio
async def test_record_creates_toxic_combination_node_and_edges():
    async with in_memory_semantic_store() as store:
        w = ToxicCombinationWriter(store, "tenant-1")
        node_id = await w.record(_combo())
        assert node_id
        # each contributor has a CONTRIBUTES_TO edge into the toxic-combination node.
        for contributor in ("P", "R", "D"):
            edges = await store.get_relationships_from(
                tenant_id="tenant-1",
                src_entity_id=contributor,
                edge_types=(EdgeType.CONTRIBUTES_TO.value,),
            )
            assert any(e.dst_entity_id == node_id for e in edges)


def test_to_hypothesis_carries_evidence_refs():
    h = to_hypothesis(_combo(), evidence_refs=("finding:dspm-1", "finding:ciem-2"))
    assert h.confidence == 1.0
    assert h.evidence_refs == ("finding:dspm-1", "finding:ciem-2")
    assert "over-permissioned" in h.statement.lower()
