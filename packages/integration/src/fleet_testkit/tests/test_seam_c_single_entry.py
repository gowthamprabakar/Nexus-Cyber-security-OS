"""NEX-106 — Seam C: the report card is the SINGLE all-paths entry (find_all alone misses the moat).

The deep seam analysis found two path systems that meet only inside the report card: the named ranker
(``find_all``) runs on pre-existing edges; the moat families (``CAN_ESCALATE_TO`` etc.) surface only via
the generic engine. A consumer calling ``find_all()`` directly would silently miss every moat path.
This test PROVES that gap and pins the contract: use ``build_report_card`` for "all paths".
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery
from meta_harness.report_card import build_report_card

from fleet_testkit import in_memory_semantic_store

_T = "seam-c"


@pytest.mark.asyncio
async def test_report_card_is_the_complete_entry_find_all_is_not() -> None:
    async with in_memory_semantic_store() as store:
        # a pure MOAT path: attacker --CAN_ESCALATE_TO--> admin --HAS_ACCESS_TO--> bucket --EXPOSES_DATA--> data
        ident = IdentityKgWriter(store, _T)
        await ident.record_escalation_grants(
            [("u:attacker", "r:admin", "self_grant_admin", "iam:CreatePolicyVersion")]
        )
        await ident.record_access([("r:admin", "arn:aws:s3:::crown")])
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::crown",
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::crown/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # find_all() (named ranker) does NOT surface the privesc moat path — it runs on old edges.
        named_types = {ap.path_type for ap in await AttackPathRanker(KgQuery(store, _T)).find_all()}
        assert "privilege_escalation" not in named_types, (
            "find_all is named-only (incomplete on its own)"
        )

        # build_report_card (the single entry) DOES surface it.
        card_types = {c.path_type for c in await build_report_card(store, _T)}
        assert "privilege_escalation" in card_types, (
            "the report card must be the complete all-paths entry"
        )
