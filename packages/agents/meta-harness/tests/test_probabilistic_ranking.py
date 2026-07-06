"""v0.5 Item 1 — end-to-end: expected-loss ranking + noisy-OR at the report-card level."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.kg_query import KgQuery
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
async def test_no_duplicate_card_for_generic_can_escalate_to_when_named_hit_exists() -> None:
    """FIX #1: _generic_path_type must return 'escalation_method_to_data' (not 'privilege_escalation')
    so the dedup bucket check in build_report_card matches the named detector's path_type and
    suppresses the generic candidate.  Without the fix, the customer sees two cards for the same
    principal→target→data path (one named 'escalation_method_to_data', one 'privilege_escalation').
    """
    t = "dedup-escalation"
    async with in_memory_semantic_store() as store:
        # Principal with external_trust=True so the generic walker starts from it as a graph source.
        principal = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:user/attacker",
            properties={"external_trust": True},
        )
        target = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:role/admin",
            properties={},
        )
        resource = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::crown",
            properties={"is_public": True},
        )
        data = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::crown/ssn",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=principal,
            dst_entity_id=target,
            relationship_type=EdgeType.CAN_ESCALATE_TO.value,
            properties={"method": "self_grant_admin"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=target,
            dst_entity_id=resource,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=resource,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        cards = await build_report_card(store, t)
        escalation_cards = [
            c for c in cards if c.path_type in {"escalation_method_to_data", "privilege_escalation"}
        ]
        # There must be exactly ONE card that covers this principal's escalation path to the data.
        # Before the fix: the generic engine returned "privilege_escalation" — different bucket from
        # the named detector's "escalation_method_to_data" → dedup missed it → count was 2.
        assert len(escalation_cards) == 1, (
            f"Expected 1 escalation card but got {len(escalation_cards)}: "
            f"{[c.path_type for c in escalation_cards]}"
        )
        assert escalation_cards[0].path_type == "escalation_method_to_data"


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
    # Uses an external-identity source (external_trust=True) so the named lateral_reachable
    # detector (which only walks CLOUD_RESOURCE is_public=True footholds) does NOT fire —
    # the path stays a GENERIC candidate whose probability uses route_probability(EDGE_TRAVERSAL_PRIOR).
    t = "load-bearing"
    async with in_memory_semantic_store() as store:
        # a novel 2-hop generic path: external_identity -CAN_REACH-> host -VULNERABLE_TO-> cve
        p = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-principal",
            properties={"external_trust": True},
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
    # Uses external-identity sources (external_trust=True) so the named lateral_reachable
    # detector (which only walks CLOUD_RESOURCE is_public=True footholds) does NOT fire —
    # these paths stay GENERIC, where route_probability carries the KEV signal.
    t = "kev-dominates"
    async with in_memory_semantic_store() as store:
        # path A: external_identity -CAN_REACH-> hostA -VULNERABLE_TO-> CVE-A (kev=True, severity=HIGH)
        pubA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-A",
            properties={"external_trust": True},
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
        # path B: external_identity -CAN_REACH-> hostB -VULNERABLE_TO-> CVE-B (kev=False, severity=HIGH)
        pubB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-B",
            properties={"external_trust": True},
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


@pytest.mark.asyncio
async def test_find_stored_secret_to_data_fires_for_non_public_workload() -> None:
    """FIX #3: find_stored_secret_to_data intentionally fires for ANY workload that stores a
    secret — not just public ones.  The NAMED_SHAPES entry carries 'public_resource' only to
    suppress the generic-engine duplicate when the workload happens to be a graph source (public).
    A private workload is a real threat (attacker inside the workload inherits the embedded
    credential's blast radius), so the detector must NOT be narrowed to is_public=True.
    """
    t = "stored-secret-non-public"
    async with in_memory_semantic_store() as store:
        # Non-public workload (no is_public property) stores a secret whose owner can reach data.
        workload = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:ecs::1:task/worker",
            properties={},  # deliberately NOT is_public=True
        )
        secret = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.SECRET.value,
            external_id="secret:api-key-123",
            properties={"secret_type": "api_key"},
        )
        owner = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:role/worker-role",
            properties={},
        )
        data_resource = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::sensitive-bucket",
            properties={"is_public": True},
        )
        dc = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::sensitive-bucket/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=workload,
            dst_entity_id=secret,
            relationship_type=EdgeType.STORES_SECRET.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=secret,
            dst_entity_id=owner,
            relationship_type=EdgeType.OWNED_BY.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=owner,
            dst_entity_id=data_resource,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=data_resource,
            dst_entity_id=dc,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        hits = await KgQuery(store, t).find_stored_secret_to_data()
        # The non-public workload MUST produce a hit — proving the broad scope is intentional.
        assert len(hits) == 1, (
            "find_stored_secret_to_data must detect secrets in non-public workloads; "
            f"got {len(hits)} hits"
        )
        assert hits[0].workload_id == workload
        assert hits[0].secret_id == secret
        assert hits[0].data_type == "ssn"
