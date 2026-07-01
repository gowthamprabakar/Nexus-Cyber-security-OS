"""W1 capstone — a realistic multi-finding tenant → the rendered report card, one entry point.

Plants several distinct real attack paths (a leaked credential, a privilege escalation, a public
over-permissioned access, an internet-exposed vulnerability) via the REAL agent writers, then calls
the single ``render_tenant_report_card`` entry point and asserts the customer sees them all, ranked
worst-first, each with a fix. The rendered card is printed so the run shows the product output.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.report_card import build_report_card, render_tenant_report_card

from fleet_testkit import in_memory_semantic_store

_T = "globex"
_AKIA = "AKIA" + "EXAMPLE0RUNNER01"
_CI = "arn:aws:iam::111:user/ci"
_DEV = "arn:aws:iam::111:user/dev"
_ADMIN = "arn:aws:iam::111:role/admin"
_CROWN = "arn:aws:s3:::crown"
_VAULT = "arn:aws:s3:::vault"
_LAKE = "arn:aws:s3:::lake"
_WEB = "arn:aws:ecs:us-east-1:111:service/web"


async def _r(store, etype, ext, props=None):
    return await store.upsert_entity(
        tenant_id=_T, entity_type=etype, external_id=ext, properties=props or {}
    )


async def _expose(store, arn):
    b = await _r(store, NodeCategory.CLOUD_RESOURCE.value, arn, {"is_public": True})
    d = await _r(store, NodeCategory.DATA_CLASSIFICATION.value, f"{arn}/pii", {"data_type": "ssn"})
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=b,
        dst_entity_id=d,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


@pytest.mark.asyncio
async def test_multi_finding_tenant_report_card() -> None:
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        # 1) leaked credential → data
        await AppsecKgWriter(store, _T).record_leaked_credentials("globex/app", [_AKIA])
        await ident.record_credential_ownership([(_CI, _AKIA)])
        await ident.record_access([(_CI, _CROWN)])
        await _expose(store, _CROWN)
        # 2) privilege escalation → data
        await ident.record_escalation_grants(
            [(_DEV, _ADMIN, "self_grant_admin", "iam:CreatePolicyVersion")]
        )
        await ident.record_access([(_ADMIN, _VAULT)])
        await _expose(store, _VAULT)
        # 3) plain over-permissioned access to public data (fine_grained)
        await ident.record_access([(_DEV, _LAKE)])
        await _expose(store, _LAKE)
        # 4) internet-exposed vulnerable workload
        web = await _r(store, NodeCategory.CLOUD_RESOURCE.value, _WEB, {"is_public": True})
        img = await _r(
            store, NodeCategory.CLOUD_RESOURCE.value, "globex/web:1", {"kind": "container-image"}
        )
        cve = await _r(
            store, NodeCategory.CVE_FINDING.value, "CVE-2024-1", {"severity": "CRITICAL"}
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=web,
            dst_entity_id=img,
            relationship_type=EdgeType.RUNS_IMAGE.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=img,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )

        rendered = await render_tenant_report_card(store, _T)
        print("\n" + rendered)

        cards = await build_report_card(store, _T)
        types = {c.path_type for c in cards}
        # the four planted risk families all reach the customer's card
        assert {
            "leaked_credential",
            "privilege_escalation",
            "fine_grained_data",
            "internet_exposed_vulnerable",
        } <= types
        # ranked worst-first + every card carries a fix
        assert [c.rank for c in cards] == sorted(c.rank for c in cards)
        assert cards[0].severity >= cards[-1].severity
        assert all(c.fix for c in cards)
        assert "# Attack Path Report Card — globex" in rendered
        assert rendered.count("**Fix:**") == len(cards)
