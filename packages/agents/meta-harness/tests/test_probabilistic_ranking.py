"""v0.5 Item 1 — end-to-end: expected-loss ranking + noisy-OR at the report-card level."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.path_priors import EDGE_TRAVERSAL_PRIOR
from meta_harness.report_card import build_report_card


async def _public_data(store, t, res, dt="ssn"):
    b = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=res,
        properties={"is_public": True},
    )
    d = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{res}/d",
        properties={"data_type": dt},
    )
    await store.add_relationship(
        tenant_id=t,
        src_entity_id=b,
        dst_entity_id=d,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return b, d


@pytest.mark.asyncio
async def test_higher_blast_radius_ranks_higher_at_equal_probability() -> None:
    t = "loss-order"
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, t)
        # admin A reaches 3 data stores; admin B reaches 1 — same path type, A has higher expected loss
        for res in ("arn:a1", "arn:a2", "arn:a3"):
            await _public_data(store, t, res)
            await ident.record_access([("arn:aws:iam::1:role/A", res)])
        await _public_data(store, t, "arn:b1")
        await ident.record_access([("arn:aws:iam::1:role/B", "arn:b1")])
        cards = await build_report_card(store, t)
        a = max(c.expected_loss for c in cards if "role/A" in " ".join(c.chain))
        b = max(c.expected_loss for c in cards if "role/B" in " ".join(c.chain))
        assert a > b


@pytest.mark.asyncio
async def test_edge_prior_table_is_load_bearing(monkeypatch) -> None:
    # Mutating the expert prior must change a generic path's probability -> guards dead config.
    t = "load-bearing"
    async with in_memory_semantic_store() as store:
        # a novel 2-hop generic path: public principal -CAN_REACH-> host -VULNERABLE_TO-> cve
        p = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:pub",
            properties={"is_public": True},
        )
        h = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:host",
            properties={},
        )
        c = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-1",
            properties={"severity": "HIGH"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=p,
            dst_entity_id=h,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=h,
            dst_entity_id=c,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        base = await build_report_card(store, t)
        base_p = max((card.probability for card in base), default=0.0)
        # belief.py imported EDGE_TRAVERSAL_PRIOR by reference — an in-place setitem on the shared
        # object is seen by route_probability. (setattr-rebind would NOT be: belief holds the old obj.)
        monkeypatch.setitem(EDGE_TRAVERSAL_PRIOR, "CAN_REACH", 0.01)
        bumped = await build_report_card(store, t)
        bumped_p = max((card.probability for card in bumped), default=0.0)
        assert bumped_p < base_p  # lowering the CAN_REACH prior lowered the path probability


@pytest.mark.asyncio
async def test_kev_dominates() -> None:
    # KEV boosts generic-path probability via leaf_probability floor (§4.4); named paths can't
    # carry KEV — this asymmetry is by design, so we test GENERIC paths only (§4.5).
    t = "kev-dominates"
    async with in_memory_semantic_store() as store:
        # path A: public_resource -CAN_REACH-> hostA -VULNERABLE_TO-> CVE-A (kev=True, severity=HIGH)
        pubA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:pubA",
            properties={"is_public": True},
        )
        hostA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:hostA",
            properties={},
        )
        cveA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-A",
            properties={"severity": "HIGH", "kev": True},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=pubA,
            dst_entity_id=hostA,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=hostA,
            dst_entity_id=cveA,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        # path B: public_resource -CAN_REACH-> hostB -VULNERABLE_TO-> CVE-B (kev=False, severity=HIGH)
        pubB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:pubB",
            properties={"is_public": True},
        )
        hostB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:hostB",
            properties={},
        )
        cveB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-B",
            properties={"severity": "HIGH", "kev": False},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=pubB,
            dst_entity_id=hostB,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=hostB,
            dst_entity_id=cveB,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        cards = await build_report_card(store, t)
        kev_card = next(c for c in cards if "arn:hostA" in c.chain)
        non_kev_card = next(c for c in cards if "arn:hostB" in c.chain)
        # KEV floor raises leaf_probability to ≥0.9 vs ~0.66 for non-KEV HIGH severity.
        assert kev_card.probability > non_kev_card.probability
