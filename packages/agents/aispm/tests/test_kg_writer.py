"""Tests for the AI-SPM knowledge-graph writer (D.11 PR5 — AI spine)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from aispm.kg_writer import KnowledgeGraphWriter
from aispm.tools.aws_ai import AwsAiInventory, SageMakerEndpoint
from aispm.tools.azure_ai import AzureAiInventory, AzureOpenAiAccount
from aispm.tools.gcp_ai import GcpAiInventory, VertexEndpoint
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_records_ai_services_models_and_bridges(store: SemanticStore) -> None:
    kg = KnowledgeGraphWriter(store, _TENANT)
    await kg.record_aws(
        AwsAiInventory(
            account_id="111122223333",
            region="us-east-1",
            sagemaker_endpoints=(
                SageMakerEndpoint(
                    name="prod",
                    data_capture_enabled=True,
                    kms_encrypted=True,
                    network_isolated=False,  # public → EXPOSES_MODEL
                    model_name="m1",
                ),
            ),
            bedrock_logging_enabled=True,
        )
    )
    await kg.record_azure(
        AzureAiInventory(
            subscription_id="sub-1",
            accounts=(
                AzureOpenAiAccount(
                    name="oai",
                    public_network_access=True,
                    network_default_allow=False,
                    cmk_encrypted=True,
                    local_auth_disabled=True,
                ),
            ),
        )
    )
    await kg.record_gcp(
        GcpAiInventory(
            project_id="proj-1",
            location="us-central1",
            endpoints=(
                VertexEndpoint(name="ep", public=False, cmk_encrypted=True, psc_enabled=True),
            ),
        )
    )

    services = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="ai_service")
    ext = {s.external_id for s in services}
    assert "sagemaker:111122223333:prod" in ext
    assert "bedrock:111122223333:bedrock" in ext
    assert "azure_openai:sub-1:oai" in ext
    assert "vertex:proj-1:ep" in ext

    models = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="ai_model")
    assert {m.external_id for m in models} == {"sagemaker:111122223333:model:m1"}

    # HOSTS_AI bridge: the AWS account node reaches the SageMaker service.
    accounts = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    aws_acct = next(a for a in accounts if a.external_id == "111122223333")
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=aws_acct.entity_id, depth=1)
    assert any(n.external_id == "sagemaker:111122223333:prod" for n in neighbors)

    # EXPOSES_MODEL: the public SageMaker + public Azure services reach the internet sentinel.
    internet = next(a for a in accounts if a.external_id == "internet")
    sm = next(s for s in services if s.external_id == "sagemaker:111122223333:prod")
    sm_neighbors = {
        n.external_id
        for n in await store.neighbors(tenant_id=_TENANT, entity_id=sm.entity_id, depth=1)
    }
    assert "internet" in sm_neighbors  # EXPOSES_MODEL
    assert "sagemaker:111122223333:model:m1" in sm_neighbors  # SERVES_MODEL
    assert internet is not None


async def test_inert_when_no_store() -> None:
    kg = KnowledgeGraphWriter(None, _TENANT)
    assert kg.enabled is False
    await kg.record_aws(
        AwsAiInventory(account_id="1", region="us-east-1", bedrock_logging_enabled=True)
    )  # must not raise
