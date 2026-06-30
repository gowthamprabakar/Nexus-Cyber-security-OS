"""Slice #1 e2e — a CAN_ESCALATE_TO edge makes a privilege-escalation-to-data path EMERGE.

Drives identity's REAL ``record_escalation_grants`` to write the edge, wires the admin's access to
sensitive data (the edges other agents write), and asserts the generic engine surfaces a candidate
path that traverses CAN_ESCALATE_TO — proving the new edge is connective, not a dead-end finding.
Also proves transitivity: two single-hop escalation edges chain through the graph on their own.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-escal"
_ATTACKER = "arn:aws:iam::111122223333:user/attacker"
_ADMIN = "arn:aws:iam::111122223333:role/admin"


async def _id_of(store, external_id: str) -> str:
    for r in await store.list_entities_by_type(
        tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
    ):
        if r.external_id == external_id:
            return r.entity_id
    raise AssertionError(f"no identity node {external_id}")


@pytest.mark.asyncio
async def test_escalation_to_data_path_emerges() -> None:
    async with in_memory_semantic_store() as store:
        # 1) identity's REAL writer lays the escalation edge: attacker -> admin.
        await IdentityKgWriter(store, _T).record_escalation_grants(
            [(_ATTACKER, _ADMIN, "self_grant_admin", "iam:AttachUserPolicy")]
        )
        # 2) the admin reaches sensitive data (edges other agents write).
        admin = await _id_of(store, _ADMIN)
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
            src_entity_id=admin,
            dst_entity_id=bucket,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # 3) the path emerges: attacker --CAN_ESCALATE_TO--> admin --HAS_ACCESS_TO--> bucket --EXPOSES_DATA--> data.
        cands = await find_candidate_paths(store, _T)
        escal = [c for c in cands if "CAN_ESCALATE_TO" in c.path.edge_signature]
        assert escal, "a privesc-to-data path must surface once CAN_ESCALATE_TO is traversable"
        path = escal[0].path
        assert path.source_id == await _id_of(store, _ATTACKER)
        assert path.sink_marker == "sensitive_data"
        assert path.edge_signature == ("CAN_ESCALATE_TO", "HAS_ACCESS_TO", "EXPOSES_DATA")


@pytest.mark.asyncio
async def test_escalation_chain_is_transitive_through_the_graph() -> None:
    # Two single-hop edges A->B, B->C chain into a reachable A->C path with NO chain logic in the
    # detector — the graph does it. (B and C are admin; C reaches data.)
    b = "arn:aws:iam::111122223333:role/mid"
    async with in_memory_semantic_store() as store:
        await IdentityKgWriter(store, _T).record_escalation_grants(
            [
                (_ATTACKER, b, "trust_rewrite", "iam:UpdateAssumeRolePolicy"),
                (b, _ADMIN, "policy_rewrite", "iam:CreatePolicyVersion"),
            ]
        )
        admin = await _id_of(store, _ADMIN)
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="d:ssn",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=admin,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        cands = await find_candidate_paths(store, _T, max_depth=4)
        attacker_id = await _id_of(store, _ATTACKER)
        # The attacker reaches data through TWO escalation hops it never had a direct edge for.
        assert any(
            c.path.source_id == attacker_id
            and c.path.sink_id == data
            and c.path.edge_signature.count("CAN_ESCALATE_TO") == 2
            for c in cands
        ), "multi-hop escalation chain must emerge from single-hop edges"
