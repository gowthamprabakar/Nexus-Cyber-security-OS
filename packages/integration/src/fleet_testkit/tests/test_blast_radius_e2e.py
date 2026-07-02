"""NEX-404 — blast-radius sizing: a principal reaching MORE data ranks/reads as higher impact."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.report_card import build_report_card, render_tenant_report_card

from fleet_testkit import in_memory_semantic_store

_T = "blast"
_ADMIN = "arn:aws:iam::1:role/admin"


async def _bucket_with_data(store, name):
    b = await store.upsert_entity(
        tenant_id=_T,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=name,
        properties={"is_public": True},
    )
    d = await store.upsert_entity(
        tenant_id=_T,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{name}/pii",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=b,
        dst_entity_id=d,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


@pytest.mark.asyncio
async def test_blast_radius_counts_reachable_data() -> None:
    async with in_memory_semantic_store() as store:
        # the admin can reach THREE data stores → blast radius 3
        for name in ("arn:aws:s3:::a", "arn:aws:s3:::b", "arn:aws:s3:::c"):
            await _bucket_with_data(store, name)
            await IdentityKgWriter(store, _T).record_access([(_ADMIN, name)])

        cards = await build_report_card(store, _T)
        assert cards, "expected at least one card"
        assert max(c.blast_radius for c in cards) == 3, (
            "admin reaches 3 data stores → blast radius 3"
        )
        rendered = await render_tenant_report_card(store, _T)
        assert "data stores at risk" in rendered  # NEX-404 rendered
        assert "**Evidence:**" in rendered and "→" in rendered  # NEX-405 the path walk
