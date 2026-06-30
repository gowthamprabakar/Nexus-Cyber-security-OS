"""Slice #3 e2e — a leaked credential's blast radius EMERGES as a cross-agent attack path.

The convergence already existed (appsec and identity key the SAME SECRET node by access-key-id), but
nothing could *walk* from a leak to its owner: ``OWNS`` points identity→secret. This drives the REAL
writers of two agents and proves the path now surfaces:
``leaked SECRET --OWNED_BY--> owner identity --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data``.
It is a genuine toxic combination: it lights up only when a credential is BOTH leaked (appsec) AND
owned by an identity that reaches data (identity) — neither agent sees it alone.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-leakcred"
_KEY = "AKIAEXAMPLE0BLASTRAD"  # non-secret access-key IDENTIFIER (the convergence key)
_USER = "arn:aws:iam::111122223333:user/ci-bot"
_BUCKET = "arn:aws:s3:::crown"


async def _node(store, category: str, external_id: str) -> str:
    for r in await store.list_entities_by_type(tenant_id=_T, entity_type=category):
        if r.external_id == external_id:
            return r.entity_id
    raise AssertionError(f"no {category} node {external_id}")


@pytest.mark.asyncio
async def test_leaked_credential_blast_radius_path_emerges() -> None:
    async with in_memory_semantic_store() as store:
        # 1) appsec: the credential is leaked in a repo (SECRET marked leaked → an attack source).
        await AppsecKgWriter(store, _T).record_leaked_credentials("org/app", [_KEY])
        # 2) identity: that key is owned by ci-bot, who can read the crown bucket.
        ident = IdentityKgWriter(store, _T)
        await ident.record_credential_ownership([(_USER, _KEY)])
        await ident.record_access([(_USER, _BUCKET)])
        # 3) the bucket holds sensitive data (the sink other agents write).
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=await _node(store, NodeCategory.CLOUD_RESOURCE.value, _BUCKET),
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        cands = await find_candidate_paths(store, _T)
        blast = [c for c in cands if "OWNED_BY" in c.path.edge_signature]
        assert blast, "a leaked-credential blast-radius path must surface once OWNED_BY is written"
        path = blast[0].path
        assert path.source_id == await _node(store, NodeCategory.SECRET.value, _KEY)
        assert path.sink_marker == "sensitive_data"
        assert path.edge_signature == ("OWNED_BY", "HAS_ACCESS_TO", "EXPOSES_DATA")


@pytest.mark.asyncio
async def test_owned_but_not_leaked_credential_does_not_create_a_source() -> None:
    # identity alone (no appsec leak) → the key is owned but not a source → no blast-radius path.
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        await ident.record_credential_ownership([(_USER, _KEY)])
        await ident.record_access([(_USER, _BUCKET)])
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=await _node(store, NodeCategory.CLOUD_RESOURCE.value, _BUCKET),
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        cands = await find_candidate_paths(store, _T)
        assert not [
            c
            for c in cands
            if c.path.source_id == await _node(store, NodeCategory.SECRET.value, _KEY)
        ]
