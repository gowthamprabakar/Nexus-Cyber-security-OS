# packages/agents/investigation/tests/test_toxic_combination.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from investigation.tools.related_findings import RelatedFinding
from investigation.toxic_combination import (
    ToxicCombinationWriter,
    detect_toxic_combination_hypotheses,
    to_hypothesis,
)
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


def _overpriv_finding(uid: str, principal_arn: str) -> RelatedFinding:
    return RelatedFinding(
        source_agent="identity",
        source_run_id="run-1",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": uid, "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app", "uid": principal_arn}],
        },
    )


async def _seed_toxic_graph(store, *, principal_arn, bucket_arn):
    t = "tenant-1"
    role = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=principal_arn,
        properties={},
    )
    bucket = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={},
    )
    data = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:ssn",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=t,
        src_entity_id=role,
        dst_entity_id=bucket,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=t,
        src_entity_id=bucket,
        dst_entity_id=data,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


@pytest.mark.asyncio
async def test_detect_emits_one_hypothesis_with_resolvable_evidence_ref():
    arn = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    async with in_memory_semantic_store() as store:
        await _seed_toxic_graph(store, principal_arn=arn, bucket_arn=bucket)
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id="tenant-1",
            related_findings=[_overpriv_finding("IDENT-OVERPRIV-app-001-x", arn)],
        )
        assert len(hyps) == 1
        assert hyps[0].evidence_refs == ("finding:IDENT-OVERPRIV-app-001-x",)
        assert "over-permissioned" in hyps[0].statement.lower()


@pytest.mark.asyncio
async def test_detect_empty_when_no_overprivilege_finding():
    async with in_memory_semantic_store() as store:
        # a 2004 finding of a different type must be ignored
        rf = RelatedFinding(
            source_agent="identity",
            source_run_id="r",
            class_uid=2004,
            payload={
                "finding_info": {"uid": "u", "types": ["dormant"]},
                "affected_principals": [{"uid": "arn:aws:iam::1:role/x"}],
            },
        )
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store, customer_id="tenant-1", related_findings=[rf]
        )
        assert hyps == ()


@pytest.mark.asyncio
async def test_detect_empty_when_principal_has_no_toxic_path():
    arn = "arn:aws:iam::1:role/app"
    async with in_memory_semantic_store() as store:
        # principal node exists but no HAS_ACCESS_TO/EXPOSES_DATA path
        await store.upsert_entity(
            tenant_id="tenant-1",
            entity_type=NodeCategory.IDENTITY.value,
            external_id=arn,
            properties={},
        )
        hyps = await detect_toxic_combination_hypotheses(
            semantic_store=store,
            customer_id="tenant-1",
            related_findings=[_overpriv_finding("IDENT-OVERPRIV-app-001-x", arn)],
        )
        assert hyps == ()
