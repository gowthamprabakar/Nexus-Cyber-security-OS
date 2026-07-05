"""The attack-path report card — merges named + novel paths into one ranked, fix-annotated list."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.attack_paths import AttackPath
from meta_harness.report_card import (
    AttackPathCard,
    build_report_card,
    rank_by_expected_loss,
    render_report_card,
)

_R = NodeCategory.CLOUD_RESOURCE.value
_ID = NodeCategory.IDENTITY.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_T = "t"


async def _node(store, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=_T, entity_type=etype, external_id=ext, properties=props
    )


async def _edge(store, src, dst, rel, props=None):
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=src,
        dst_entity_id=dst,
        relationship_type=rel,
        properties=props or {},
    )


@pytest.mark.asyncio
async def test_card_merges_named_privesc_method_and_direct_access_ranked_with_fixes():
    async with in_memory_semantic_store() as store:
        # NAMED C-3 path (escalation_method_to_data): attacker --CAN_ESCALATE_TO--> admin
        # --HAS_ACCESS_TO--> bucket --EXPOSES_DATA--> ssn. Now a named archetype (C-3) surfaced by
        # the named ranker, not the generic engine.
        attacker = await _node(store, _ID, "arn:aws:iam::1:user/attacker", {})
        admin = await _node(store, _ID, "arn:aws:iam::1:role/admin", {})
        crown = await _node(store, _R, "arn:aws:s3:::crown", {"is_public": True})
        data = await _node(store, _DC, "arn:aws:s3:::crown/pii", {"data_type": "ssn"})
        await _edge(
            store, attacker, admin, EdgeType.CAN_ESCALATE_TO.value, {"method": "self_grant_admin"}
        )
        await _edge(store, admin, crown, EdgeType.HAS_ACCESS_TO.value)
        await _edge(store, crown, data, EdgeType.EXPOSES_DATA.value)
        # NAMED path: a plain over-permissioned principal reading the same public bucket's data.
        reader = await _node(store, _ID, "arn:aws:iam::1:user/reader", {})
        await _edge(store, reader, crown, EdgeType.HAS_ACCESS_TO.value)

        cards = await build_report_card(store, _T)

        by_type = {c.path_type: c for c in cards}
        assert "escalation_method_to_data" in by_type, (
            "the named escalation-method-to-data path must appear on the card (C-3)"
        )
        assert "fine_grained_data" in by_type, "the named path must appear too"
        # v0.5: ranking is now expected-loss, not severity. Both routes reach the same sink with the
        # same blast radius, so they tie on expected loss; impact-driven order is covered by
        # test_probabilistic_ranking.test_higher_blast_radius_ranks_higher. Here we assert both the
        # named and fine-grained paths surface and each carries its fix.
        assert (
            by_type["escalation_method_to_data"].rank != by_type["fine_grained_data"].rank
        )  # distinct ranks
        # Every card carries a concrete fix.
        assert all(c.fix and c.fix != "" for c in cards)
        assert "least privilege" in by_type["escalation_method_to_data"].fix


@pytest.mark.asyncio
async def test_empty_graph_renders_clean_card():
    async with in_memory_semantic_store() as store:
        cards = await build_report_card(store, _T)
        assert cards == []
        assert "No attack paths found" in render_report_card(cards, tenant=_T)


def test_render_lists_rank_severity_and_fix():
    cards = [
        AttackPathCard(
            rank=1,
            severity=92,
            path_type="leaked_credential",
            title="A credential leaked in code reaches sensitive data through its owner",
            chain=("secretfp:abc", "arn:aws:iam::1:user/ci", "arn:aws:s3:::crown"),
            fix="Rotate and revoke the exposed credential now.",
        )
    ]
    out = render_report_card(cards, tenant="acme")
    assert "# Attack Path Report Card — acme" in out
    assert "severity 92]" in out  # NEX-403: header now "[P … · loss … · severity 92]"
    assert "**Fix:** Rotate and revoke" in out
    assert "leaked_credential" in out


# ---------------------------------------------------------------------------
# Task 3: rank_by_expected_loss — reusable ranker with real KEV/EPSS + broader blast
# ---------------------------------------------------------------------------

_R2 = NodeCategory.CLOUD_RESOURCE.value
_ID2 = NodeCategory.IDENTITY.value
_DC2 = NodeCategory.DATA_CLASSIFICATION.value
_SEV = 80  # equal severity for both paths in the ordering tests


async def _wire_principal_to_n_data_stores(store, tenant, principal_ext, n):
    """Wire principal -HAS_ACCESS_TO-> public_resource -EXPOSES_DATA-> data_class (x n)."""
    principal = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_ID2,
        external_id=principal_ext,
        properties={},
    )
    data_ids = []
    for i in range(n):
        res = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_R2,
            external_id=f"{principal_ext}/res{i}",
            properties={"is_public": True},
        )
        dc = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_DC2,
            external_id=f"{principal_ext}/dc{i}",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=principal,
            dst_entity_id=res,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=res,
            dst_entity_id=dc,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        data_ids.append(dc)
    return principal, data_ids


@pytest.mark.asyncio
async def test_rank_by_expected_loss_high_blast_ranks_first() -> None:
    """High-blast path must rank above low-blast path at equal severity (kev=False)."""
    tenant = "rl-blast-order"
    async with in_memory_semantic_store() as store:
        # Path A: principal reaches 3 data stores → blast=3
        principalA, dcsA = await _wire_principal_to_n_data_stores(store, tenant, "arn:role/A", 3)
        # Path B: principal reaches 1 data store → blast=1
        principalB, dcsB = await _wire_principal_to_n_data_stores(store, tenant, "arn:role/B", 1)

        path_a = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="path A — high blast",
            entities=(principalA,),
            sink_id=dcsA[0],
        )
        path_b = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="path B — low blast",
            entities=(principalB,),
            sink_id=dcsB[0],
        )

        ranked = await rank_by_expected_loss([path_a, path_b], store, tenant)

        assert len(ranked) == 2, "ranker must be total — every input path appears in output"
        first_path, first_loss, first_blast = ranked[0]
        _second_path, second_loss, second_blast = ranked[1]

        assert first_blast > second_blast, (
            f"expected high-blast (A, blast={first_blast}) before low-blast (B, blast={second_blast})"
        )
        assert first_loss > second_loss, (
            f"expected higher expected-loss for high-blast path: {first_loss} vs {second_loss}"
        )
        assert first_path.title == "path A — high blast", (
            f"wrong path ranked first: {first_path.title}"
        )


@pytest.mark.asyncio
async def test_rank_by_expected_loss_kev_outranks_non_kev_at_equal_severity_and_blast() -> None:
    """A KEV path must outrank an identical-severity/blast non-KEV path — proving the KEV lift.

    Title ordering is deliberately adversarial: "aaa exposure" (non-KEV) sorts BEFORE "zzz exposure"
    (KEV) alphabetically, so only the KEV lift (via leaf_probability(kev=True)) can put the KEV path
    first. If kev isn't threaded through leaf_probability, this test fails.
    """
    tenant = "rl-kev-lift"
    async with in_memory_semantic_store() as store:
        # Both paths: principal reaches 1 data store (equal blast)
        principalK, dcsK = await _wire_principal_to_n_data_stores(store, tenant, "arn:role/K", 1)
        principalN, dcsN = await _wire_principal_to_n_data_stores(store, tenant, "arn:role/N", 1)

        path_kev = AttackPath(
            path_type="internet_exposed_vulnerable",
            severity=_SEV,
            title="zzz exposure",  # sorts LAST alphabetically — only KEV lift can push it first
            entities=(principalK,),
            sink_id=dcsK[0],
            kev=True,
            epss=None,
        )
        path_non_kev = AttackPath(
            path_type="internet_exposed_vulnerable",
            severity=_SEV,
            title="aaa exposure",  # sorts FIRST alphabetically — would win without KEV lift
            entities=(principalN,),
            sink_id=dcsN[0],
            kev=False,
            epss=None,
        )

        ranked = await rank_by_expected_loss([path_kev, path_non_kev], store, tenant)

        assert len(ranked) == 2, "ranker must be total"
        first_path, first_loss, _blast = ranked[0]

        assert first_path.title == "zzz exposure", (
            f"KEV path ('zzz exposure') must rank first despite alphabetical disadvantage, "
            f"but got: {first_path.title!r} (loss={first_loss:.4f}). "
            f"KEV lift is not flowing through leaf_probability."
        )


@pytest.mark.asyncio
async def test_rank_by_expected_loss_resource_reach_blast_not_fallback() -> None:
    """_blast must count data stores via resource_reach, not fall back to 1 for resource-entity paths.

    Topology: one principal --> HAS_ACCESS_TO --> resource --> EXPOSES_DATA --> dc_i (x N).
    find_fine_grained_data_exposure populates resource_reach[resource_id] = {dc_0, ..., dc_{N-1}}.
    The AttackPath's entities contain ONLY the resource_id (not the principal).
    Before the broadening, _blast would miss resource_reach and return blast=1.
    After the broadening, _blast returns N.
    """
    tenant = "rl-resource-reach"
    N = 4  # number of distinct data stores the resource exposes
    async with in_memory_semantic_store() as store:
        # Create a CLOUD_RESOURCE node (the "exposed database")
        resource_id = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_R2,
            external_id="arn:aws:rds::123:db/exposed-db",
            properties={"is_public": True},
        )
        # Create a principal that has access to the resource (needed so find_fine_grained_data_exposure
        # traverses the resource and populates resource_reach).
        principal_id = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_ID2,
            external_id="arn:aws:iam::123:role/reader",
            properties={},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=principal_id,
            dst_entity_id=resource_id,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        # Wire resource --EXPOSES_DATA--> dc_i (x N distinct data stores)
        for i in range(N):
            dc_id = await store.upsert_entity(
                tenant_id=tenant,
                entity_type=_DC2,
                external_id=f"arn:aws:s3:::crown/pii-{i}",
                properties={"data_type": "ssn"},
            )
            await store.add_relationship(
                tenant_id=tenant,
                src_entity_id=resource_id,
                dst_entity_id=dc_id,
                relationship_type=EdgeType.EXPOSES_DATA.value,
                properties={},
            )

        # The path's entities contain the RESOURCE node only (exposed_database shape).
        # If _blast only checked principal_reach, it would return 1 (resource_id not in principal_reach).
        path = AttackPath(
            path_type="exposed_database",
            severity=_SEV,
            title="exposed db reaches N data stores",
            entities=(resource_id,),
            sink_id="",
            kev=False,
            epss=None,
        )

        ranked = await rank_by_expected_loss([path], store, tenant)

        assert len(ranked) == 1
        _, _el, blast = ranked[0]
        assert blast == N, (
            f"resource_reach blast must be {N} (one per data store), got {blast}. "
            f"_blast is not traversing resource_reach for entity {resource_id!r}."
        )
