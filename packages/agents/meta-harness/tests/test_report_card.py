"""The attack-path report card — merges named + novel paths into one ranked, fix-annotated list."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.report_card import (
    AttackPathCard,
    build_report_card,
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
async def test_card_merges_novel_privesc_and_named_path_ranked_with_fixes():
    async with in_memory_semantic_store() as store:
        # NOVEL moat path (generic engine): attacker --CAN_ESCALATE_TO--> admin --HAS_ACCESS_TO-->
        # bucket --EXPOSES_DATA--> ssn. Not a named archetype → only the report card surfaces it.
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
        assert "privilege_escalation" in by_type, "the novel moat path must appear on the card"
        assert "fine_grained_data" in by_type, "the named path must appear too"
        # Worst-first: privilege_escalation (sev 66) outranks fine_grained_data (sev 60).
        assert by_type["privilege_escalation"].rank < by_type["fine_grained_data"].rank
        # Every card carries a concrete fix.
        assert all(c.fix and c.fix != "" for c in cards)
        assert "least privilege" in by_type["privilege_escalation"].fix


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
    assert "[severity 92]" in out
    assert "**Fix:** Rotate and revoke" in out
    assert "leaked_credential" in out
