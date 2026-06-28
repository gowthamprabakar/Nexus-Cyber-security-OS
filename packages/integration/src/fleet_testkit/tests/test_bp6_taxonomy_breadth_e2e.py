"""BP6 — taxonomy breadth: the generic engine now sees the AI-model + SaaS domains, REAL feeders.

Before BP6 the engine was blind to AI models (SERVES_MODEL not traversable, AI_MODEL not a sink)
and SaaS tenants (AUTHORIZED not traversable, OAUTH_APP/SAAS_TENANT unmarked). These drive the REAL
AI-SPM (moto SageMaker) and SSPM (Slack connector) writers and assert the new candidate shapes
surface — and that a read-only OAuth app does NOT (the over-scoped predicate gives precision).
"""

import pytest
from meta_harness.path_engine import find_candidate_paths
from sspm.kg_writer import KnowledgeGraphWriter as SspmWriter
from sspm.tools.slack import SlackOAuthApp, SlackWorkspaceInventory

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_aispm, moto_ai_clients, setup_sagemaker_endpoint

_T = "tenant-bp6"


def _shapes(cands):
    return {(c.path.source_marker, c.path.sink_marker, c.path.edge_signature) for c in cands}


@pytest.mark.asyncio
async def test_ai_model_candidate_surfaces_from_real_aispm() -> None:
    async with in_memory_semantic_store() as store:
        with moto_ai_clients(()) as (_s3, sm):
            setup_sagemaker_endpoint(
                sm, name="fraud", model_data_bucket="m", network_isolated=False
            )
            await drive_aispm(store, tenant_id=_T, sm_client=sm)
        cands = await find_candidate_paths(store, _T)
        assert ("exposed_ai_service", "ai_model", ("SERVES_MODEL",)) in _shapes(cands)


def _slack_inventory(scopes: tuple[str, ...]) -> SlackWorkspaceInventory:
    return SlackWorkspaceInventory(
        team_id="T1",
        team_name="Acme",
        owners=1,
        admins=1,
        guests=0,
        members_without_2fa=0,
        oauth_apps=(SlackOAuthApp(app_id="A1", name="Bot", scopes=scopes),),
    )


@pytest.mark.asyncio
async def test_over_scoped_oauth_candidate_surfaces_from_real_sspm() -> None:
    async with in_memory_semantic_store() as store:
        await SspmWriter(store, _T).record_slack(_slack_inventory(("admin",)))
        cands = await find_candidate_paths(store, _T)
        assert ("over_scoped_oauth_app", "saas_tenant", ("AUTHORIZED",)) in _shapes(cands)


@pytest.mark.asyncio
async def test_read_only_oauth_app_is_not_a_candidate() -> None:
    # Precision: a read-only app is not an over-scoped exposure → no SaaS candidate.
    async with in_memory_semantic_store() as store:
        await SspmWriter(store, _T).record_slack(_slack_inventory(("channels:read",)))
        assert await find_candidate_paths(store, _T) == []
