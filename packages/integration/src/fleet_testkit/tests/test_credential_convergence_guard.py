"""NEX-408 — credential SECRET-node convergence guard (the smoke-bug class).

Three agents key a leaked AWS credential by its access-key-id: appsec (leaked in code), identity
(owned by a user), cloud-posture (embedded in a workload's env). If their extractions disagree by even
one char, they land on DIFFERENT SECRET nodes and the blast-radius path silently breaks (exactly the
bug the full-moat smoke hit: AKIA+17 vs the AKIA+16 regex). This pins that they converge on ONE node.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import NodeCategory
from cloud_posture.tools.stored_secrets import stored_secret_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter

from fleet_testkit import in_memory_semantic_store

_T = "conv"
_KEY = "AKIA" + "EXAMPLECONVERG01"  # canonical: AKIA + exactly 16 chars


def test_stored_secret_extraction_equals_the_raw_key_id():
    # cloud-posture's env extraction must yield EXACTLY the key id identity/appsec store verbatim.
    grants = stored_secret_grants([("svc:web", [f"AWS_ACCESS_KEY_ID={_KEY}"])])
    assert grants == [("svc:web", _KEY)], "env-extracted key must equal the canonical key id"


@pytest.mark.asyncio
async def test_three_agents_converge_on_one_secret_node() -> None:
    async with in_memory_semantic_store() as store:
        # appsec: leaked in code
        await AppsecKgWriter(store, _T).record_leaked_credentials("o/a", [_KEY])
        # identity: owned by a user
        await IdentityKgWriter(store, _T).record_credential_ownership([("u:ci", _KEY)])
        # (cloud-posture would write STORES_SECRET to the same key via stored_secret_grants)
        secrets = [
            r.external_id
            for r in await store.list_entities_by_type(
                tenant_id=_T, entity_type=NodeCategory.SECRET.value
            )
        ]
        assert secrets.count(_KEY) == 1, "appsec + identity must share ONE SECRET node"
        assert len(set(secrets)) == 1, "no divergent SECRET nodes for the same credential"
