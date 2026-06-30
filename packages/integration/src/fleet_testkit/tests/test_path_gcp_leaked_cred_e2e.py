"""Slice #3 on GCP — a leaked SA key's blast radius emerges via HASHED convergence.

Same shape as the AWS leaked-cred e2e, but the SECRET node key is ``secret_fingerprint(private_key_id)``
on BOTH sides — appsec hashes the leaked JSON's id, identity hashes the IAM key-list id — so leak ⇄
owner converge with NOTHING readable stored (the operator-chosen contract-safe design). Proves the
path emerges across two agents and a third cloud, and that the trap (owned-not-leaked) stays dark.
"""

import json

import pytest
from appsec.gcp_sa_key import leaked_sa_key_fingerprints
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.canonical import gcs_uri
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.gcp_iam import GcpServiceAccountKey, sa_key_ownership
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-gcpleak"
_SA = "ci@prod-1.iam.gserviceaccount.com"
_KEY_ID = "abc123def456"
_BUCKET = gcs_uri("crown")
_SA_KEY_JSON = json.dumps(
    {"type": "service_account", "private_key": "x", "private_key_id": _KEY_ID, "client_email": _SA}
)


async def _node(store, category: str, external_id: str) -> str:
    for r in await store.list_entities_by_type(tenant_id=_T, entity_type=category):
        if r.external_id == external_id:
            return r.entity_id
    raise AssertionError(f"no {category} node {external_id}")


@pytest.mark.asyncio
async def test_gcp_leaked_sa_key_blast_radius_emerges() -> None:
    leaked = leaked_sa_key_fingerprints((_SA_KEY_JSON,))
    owned = sa_key_ownership((GcpServiceAccountKey(_SA, _KEY_ID),))
    async with in_memory_semantic_store() as store:
        # appsec: the SA key is leaked in a repo (SECRET{leaked, gcp-sa-key}, keyed by the hash).
        await AppsecKgWriter(store, _T).record_leaked_credentials(
            "org/app", leaked, kind="gcp-sa-key"
        )
        # identity: that SA owns the key (same hash) and can read the crown bucket.
        ident = IdentityKgWriter(store, _T)
        await ident.record_sa_credential_ownership(owned)
        await ident.record_access([(_SA, _BUCKET)])
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
        assert blast, "the leaked GCP SA key's blast radius must surface via hashed convergence"
        path = blast[0].path
        assert path.source_id == await _node(store, NodeCategory.SECRET.value, leaked[0])
        assert path.sink_marker == "sensitive_data"
        assert path.edge_signature == ("OWNED_BY", "HAS_ACCESS_TO", "EXPOSES_DATA")


@pytest.mark.asyncio
async def test_gcp_owned_but_not_leaked_stays_dark() -> None:
    owned = sa_key_ownership((GcpServiceAccountKey(_SA, _KEY_ID),))
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        await ident.record_sa_credential_ownership(owned)  # owner, but no appsec leak
        await ident.record_access([(_SA, _BUCKET)])
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
            if c.path.source_id == await _node(store, NodeCategory.SECRET.value, owned[0][1])
        ]
