"""NEX-004a — identity.run() is fixture-drivable → it populates the graph OFFLINE (the dormancy fix).

Before this, identity's detectors only wrote to the graph in unit tests calling the writers directly;
a real run() read live IAM. This proves a fixture ``IdentityListing`` drives ``identity.run()`` with a
``semantic_store`` and the graph gets identity's real edges — so a fixture-driven operating run builds
the moat, not just tests. (JSON-file feed is a thin follow-on; injectable listing is the core.)
"""

from datetime import UTC, datetime

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.agent import run as identity_run
from identity.tools.aws_iam import IamUser, IdentityListing

from fleet_testkit import in_memory_semantic_store

_DATE = datetime(2026, 7, 2, tzinfo=UTC)
_ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN = "arn:aws:iam::111122223333:user/admin"
_BUCKET = "arn:aws:s3:::crown"


def _contract(tmp_path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_test",
        task="fixture run",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=500, mb_written=10
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
            "detect_aws_saml_providers",
            "detect_aws_oidc_providers",
            "detect_azure_federated_domains",
            "detect_azure_oidc_providers",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=_DATE,
        expires_at=datetime(2026, 7, 3, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_fixture_listing_drives_run_and_populates_the_graph(tmp_path) -> None:
    listing = IdentityListing(
        users=(
            IamUser(
                arn=_ADMIN,
                name="admin",
                user_id="AIDA1",
                create_date=_DATE,
                last_used_at=None,
                attached_policy_arns=(_ADMIN_POLICY,),
            ),
        ),
        roles=(),
        groups=(),
    )
    async with in_memory_semantic_store() as store:
        # a resource for the admin to reach (data-security/cloud-posture own this in a real run)
        await store.upsert_entity(
            tenant_id="cust_test",
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_BUCKET,
            properties={},
        )
        # drive identity.run() OFFLINE with the fixture listing
        await identity_run(_contract(tmp_path), iam_listing=listing, semantic_store=store)

        # run() wrote the IDENTITY inventory node...
        idents = {
            r.external_id
            for r in await store.list_entities_by_type(
                tenant_id="cust_test", entity_type=NodeCategory.IDENTITY.value
            )
        }
        assert _ADMIN in idents, "run() must write identity nodes from the fixture listing"
        # ...and the HAS_ACCESS_TO moat edge (admin → the resource) — a real run built graph content.
        admin_id = next(
            r.entity_id
            for r in await store.list_entities_by_type(
                tenant_id="cust_test", entity_type=NodeCategory.IDENTITY.value
            )
            if r.external_id == _ADMIN
        )
        access = await store.get_relationships_from(
            tenant_id="cust_test",
            src_entity_id=admin_id,
            edge_types=(EdgeType.HAS_ACCESS_TO.value,),
        )
        assert access, (
            "run() must write the admin's HAS_ACCESS_TO edges (the dormancy fix in action)"
        )
