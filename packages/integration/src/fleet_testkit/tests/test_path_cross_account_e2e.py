"""W3 e2e — cross-account trust abuse emerges as an attack path.

A role trusts a foreign account; that external principal assumes it and reaches data. Drives the REAL
detector + the existing writers (record_external_trust marks the source, record_assume_grants writes
ASSUMES) and proves the walk:
``external principal --ASSUMES--> role --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data``.
"""

from datetime import UTC, datetime

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.aws_iam import IamRole
from identity.tools.cross_account import cross_account_trust_grants
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-xacct"
_HOME = "111111111111"
_FOREIGN = "999999999999"
_ROLE = f"arn:aws:iam::{_HOME}:role/partner"
_FOREIGN_P = f"arn:aws:iam::{_FOREIGN}:root"
_BUCKET = "arn:aws:s3:::crown"


@pytest.mark.asyncio
async def test_cross_account_trust_path_emerges() -> None:
    role = IamRole(
        arn=_ROLE,
        name="partner",
        role_id="AROA1",
        create_date=datetime(2026, 7, 1, tzinfo=UTC),
        last_used_at=None,
        assume_role_policy_document={
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": _FOREIGN_P}, "Action": "sts:AssumeRole"}
            ]
        },
    )
    grants = cross_account_trust_grants([role])
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, _T)
        # mark the foreign principal external (the source) + write the ASSUMES edge
        await ident.record_external_trust([p for p, _ in grants])
        await ident.record_assume_grants(grants)
        # the role reaches the crown bucket's data (cloud side)
        await ident.record_access([(_ROLE, _BUCKET)])
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        cands = await find_candidate_paths(store, _T)
        xacct = [
            c
            for c in cands
            if c.path.source_marker == "external_identity" and "ASSUMES" in c.path.edge_signature
        ]
        assert xacct, "a foreign principal assuming a cross-account role to data must surface"
        assert xacct[0].path.edge_signature == ("ASSUMES", "HAS_ACCESS_TO", "EXPOSES_DATA")
        assert xacct[0].path.sink_marker == "sensitive_data"
