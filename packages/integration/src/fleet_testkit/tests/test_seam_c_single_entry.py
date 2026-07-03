"""NEX-106 — Seam C: the report card is the SINGLE all-paths entry.

The deep seam analysis found two path systems that meet only inside the report card: the named ranker
(``find_all``) runs on named detectors; the generic engine surfaces any remaining novel moat paths.
A consumer calling ``find_all()`` directly would silently miss generic-engine-only paths.

C-3 NOTE: ``CAN_ESCALATE_TO`` was previously a generic-only moat path. After C-3 it is the NAMED
detector ``escalation_method_to_data`` — ``find_all()`` now surfaces it directly. The test is updated
to verify C-3 is both named AND surfaces on the report card (the contract still holds: the report card
is still the preferred single entry; the seam gap now applies to remaining un-named generic paths).
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
        # C-3 NAMED path: attacker --CAN_ESCALATE_TO--> admin --HAS_ACCESS_TO--> bucket
        # --EXPOSES_DATA--> data. After C-3 this is a NAMED detector, so find_all() surfaces it.
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

        # After C-3: find_all() (named ranker) DOES surface the escalation-method-to-data path.
        named_types = {ap.path_type for ap in await AttackPathRanker(KgQuery(store, _T)).find_all()}
        assert "escalation_method_to_data" in named_types, (
            "after C-3 the named ranker must surface escalation_method_to_data"
        )

        # build_report_card (the single entry) also surfaces it.
        card_types = {c.path_type for c in await build_report_card(store, _T)}
        assert "escalation_method_to_data" in card_types, (
            "the report card must surface the escalation-method-to-data path (C-3)"
        )
