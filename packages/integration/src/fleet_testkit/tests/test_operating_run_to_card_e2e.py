"""NEX-004c — the operating path end-to-end: a real agent run() → graph → report card.

Ties the wire-as-we-go pieces together: a fixture drives identity.run() (a REAL agent run, offline),
which populates the shared graph, and render_tenant_report_card turns that graph into the ranked card
— no hand-seeded edges. This is "the moat OPERATES", not just "the moat is proven in unit tests".
"""

from datetime import UTC, datetime

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.agent import run as identity_run
from identity.tools.aws_iam import IamUser, IdentityListing
from meta_harness.report_card import build_report_card, render_tenant_report_card

from fleet_testkit import in_memory_semantic_store

_DATE = datetime(2026, 7, 2, tzinfo=UTC)
_ADMIN = "arn:aws:iam::111122223333:user/admin"
_BUCKET = "arn:aws:s3:::crown"
_TENANT = "cust_test"


def _contract(tmp_path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1", delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ", source_agent="supervisor",
        target_agent="identity", customer_id=_TENANT, task="operating run",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=500, mb_written=10),
        permitted_tools=["aws_iam_list_identities", "aws_iam_simulate_principal_policy",
                         "aws_access_analyzer_findings", "detect_aws_saml_providers",
                         "detect_aws_oidc_providers", "detect_azure_federated_domains",
                         "detect_azure_oidc_providers"],
        completion_condition="findings.json AND summary.md exist", escalation_rules=[],
        workspace=str(tmp_path / "ws"), persistent_root=str(tmp_path / "p"),
        created_at=_DATE, expires_at=datetime(2026, 7, 3, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_agent_run_populates_graph_then_report_card_renders(tmp_path) -> None:
    listing = IdentityListing(
        users=(IamUser(arn=_ADMIN, name="admin", user_id="AIDA1", create_date=_DATE,
                       last_used_at=None, attached_policy_arns=("arn:aws:iam::aws:policy/AdministratorAccess",)),),
        roles=(), groups=(),
    )
    async with in_memory_semantic_store() as store:
        # a public bucket exposing data (data-security/cloud-posture own this in a real run)
        bucket = await store.upsert_entity(tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                           external_id=_BUCKET, properties={"is_public": True})
        data = await store.upsert_entity(tenant_id=_TENANT, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                         external_id=f"{_BUCKET}/pii", properties={"data_type": "ssn"})
        await store.add_relationship(tenant_id=_TENANT, src_entity_id=bucket, dst_entity_id=data,
                                     relationship_type=EdgeType.EXPOSES_DATA.value, properties={})

        # OPERATING RUN: a real agent run() builds the identity→data access, no hand-seeded edges
        await identity_run(_contract(tmp_path), iam_listing=listing, semantic_store=store)

        # the report card renders a path off the graph the run() built
        cards = await build_report_card(store, _TENANT)
        assert cards, "the operating run must yield at least one attack-path card"
        assert any("data" in c.path_type or c.path_type == "fine_grained_data" for c in cards)
        rendered = await render_tenant_report_card(store, _TENANT)
        assert "# Attack Path Report Card" in rendered and "**Fix:**" in rendered
