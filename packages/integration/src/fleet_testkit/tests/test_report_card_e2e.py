"""End-to-end report card — plant a realistic scenario, run REAL agent writers, see the top paths.

No cloud account: a planted scenario drives the REAL graph-writing code of two agents (appsec +
identity) plus a public-data exposure, then the REAL path engine + ranker + report card produce the
customer-facing "top attack paths, prioritized, each with a fix." The per-edge DETECTORS are unit-
tested in their slices; this proves the whole pipeline — graph → ranked report card — works together.
The rendered card is printed so the run literally shows the product output.
"""

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppsecKgWriter
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.report_card import build_report_card, render_report_card

from fleet_testkit import in_memory_semantic_store

_T = "acme-corp"
_AKIA = "AKIAEXAMPLE0REPORTC1"  # non-secret AWS key IDENTIFIER (the approved plaintext)
_CI_USER = "arn:aws:iam::111122223333:user/ci-bot"
_ATTACKER = "arn:aws:iam::111122223333:user/dev"
_ADMIN = "arn:aws:iam::111122223333:role/admin"
_CROWN = "arn:aws:s3:::crown-jewels"
_VAULT = "arn:aws:s3:::vault"


async def _r(store, etype, ext, props=None):
    return await store.upsert_entity(
        tenant_id=_T, entity_type=etype, external_id=ext, properties=props or {}
    )


async def _expose(store, bucket_arn):
    """Make a public bucket that EXPOSES_DATA → ssn (the sink other agents write)."""
    bucket = await _r(store, NodeCategory.CLOUD_RESOURCE.value, bucket_arn, {"is_public": True})
    data = await _r(
        store, NodeCategory.DATA_CLASSIFICATION.value, f"{bucket_arn}/pii", {"data_type": "ssn"}
    )
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=bucket,
        dst_entity_id=data,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


@pytest.mark.asyncio
async def test_report_card_surfaces_planted_paths_with_fixes(capsys) -> None:
    async with in_memory_semantic_store() as store:
        appsec = AppsecKgWriter(store, _T)
        ident = IdentityKgWriter(store, _T)

        # PLANT 1 — leaked credential blast radius: ci-bot's key is committed to a repo and the key
        # can read the crown jewels.
        await appsec.record_leaked_credentials("acme/web", [_AKIA])
        await ident.record_credential_ownership([(_CI_USER, _AKIA)])
        await ident.record_access([(_CI_USER, _CROWN)])
        await _expose(store, _CROWN)

        # PLANT 2 — privilege escalation: dev can self-grant admin, and admin reads the vault.
        await ident.record_escalation_grants(
            [(_ATTACKER, _ADMIN, "self_grant_admin", "iam:CreatePolicyVersion")]
        )
        await ident.record_access([(_ADMIN, _VAULT)])
        await _expose(store, _VAULT)

        cards = await build_report_card(store, _T)
        print("\n" + render_report_card(cards, tenant=_T))  # show the product output

        by_type = {c.path_type: c for c in cards}
        # Both planted moat paths surface on the customer's report card...
        assert "leaked_credential" in by_type
        assert "privilege_escalation" in by_type
        # ...ranked worst-first: a leaked credential (92) outranks privilege escalation (66).
        assert by_type["leaked_credential"].rank == 1
        assert by_type["leaked_credential"].rank < by_type["privilege_escalation"].rank
        # ...each with a concrete, actionable fix.
        assert "Rotate and revoke" in by_type["leaked_credential"].fix
        assert "least privilege" in by_type["privilege_escalation"].fix

        rendered = render_report_card(cards, tenant=_T)
        assert "# Attack Path Report Card — acme-corp" in rendered
        assert "**Fix:**" in rendered
