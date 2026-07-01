"""Slice #3 on Azure — a leaked SP secret's blast radius emerges via hashed convergence.

Completes the leaked-credential edge on the 3rd cloud: appsec hashes the leaked SP's client-id,
identity hashes the SP's appId — same hash → one SECRET node, nothing readable stored. Proves the
walk ``leaked SP secret --OWNED_BY--> service principal --HAS_ACCESS_TO--> blob --EXPOSES_DATA--> data``.
"""

import pytest
from appsec.azure_sp_secret import leaked_azure_sp_secrets
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.canonical import azure_blob_uri
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.azure_ad import AzureAdServicePrincipal, azure_sp_key, sp_credential_ownership
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-azsp"
_APPID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_BLOB = azure_blob_uri("acct", "pii")


@pytest.mark.asyncio
async def test_azure_leaked_sp_secret_blast_radius_emerges() -> None:
    sp = AzureAdServicePrincipal(
        id="obj-1", app_id=_APPID, display_name="ci-sp", sp_type="Application", account_enabled=True
    )
    leaked = leaked_azure_sp_secrets([("AZURE_CLIENT_ID", _APPID), ("AZURE_CLIENT_SECRET", "sekret")])
    owned = sp_credential_ownership((sp,))
    async with in_memory_semantic_store() as store:
        await AppsecKgWriter(store, _T).record_leaked_credentials("acme/infra", leaked, kind="azure-sp-secret")
        ident = IdentityKgWriter(store, _T)
        await ident.record_sp_credential_ownership(owned)
        await ident.record_access([(azure_sp_key(_APPID), _BLOB)])
        blob = await store.upsert_entity(
            tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value, external_id=_BLOB, properties={}
        )
        data = await store.upsert_entity(
            tenant_id=_T, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BLOB}:pii", properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T, src_entity_id=blob, dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value, properties={},
        )

        cands = await find_candidate_paths(store, _T)
        blast = [c for c in cands if "OWNED_BY" in c.path.edge_signature]
        assert blast, "the leaked Azure SP secret's blast radius must surface via hashed convergence"
        assert blast[0].path.edge_signature == ("OWNED_BY", "HAS_ACCESS_TO", "EXPOSES_DATA")
        assert blast[0].path.sink_marker == "sensitive_data"
