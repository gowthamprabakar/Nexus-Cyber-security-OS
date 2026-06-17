"""AI-SPM knowledge-graph writer (v0.4 D.11 PR5 — AI inventory on the coherent spine).

Consumes the typed cloud-discovery inventories and writes the AI inventory into the fleet
graph as the first consumer of ADR-018's scaffolded AI vocabulary:

- ``AI_SERVICE`` nodes — discovered deployments (SageMaker / Bedrock / Azure OpenAI / Vertex).
- ``AI_MODEL`` nodes — the served model.
- ``SERVES_MODEL`` — AI service → model.
- ``EXPOSES_MODEL`` — a publicly-reachable AI service → an ``internet`` sentinel (the
  internet-exposure surface; queryable as "all AI services exposed to the internet").
- ``HOSTS_AI`` — the cloud account → AI service: the **cross-domain bridge** to the
  ``CLOUD_RESOURCE`` account node the posture agents own (D.11's analogue of D.6's IRSA
  bridge), closing on the same coherent spine. Full account-node reconciliation with the
  posture agents is Stage 3.

``TRAINED_ON`` / ``INFERENCES_LOGGED_TO`` are opportunistic — written only when discovery
surfaces the dataset / capture-bucket id (not yet collected → not drawn; surfaced, not faked).

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed vocabulary,
within-run dedup, opt-in/inert. Reads typed inventories, never OCSF findings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

if TYPE_CHECKING:
    from aispm.tools.aws_ai import AwsAiInventory
    from aispm.tools.azure_ai import AzureAiInventory
    from aispm.tools.gcp_ai import GcpAiInventory

_INTERNET_EXTERNAL_ID = "internet"


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists AI service/model nodes + SERVES_MODEL / EXPOSES_MODEL / HOSTS_AI edges."""

    async def _account_node(self, provider: str, account_id: str) -> str | None:
        return await self.upsert_node(
            NodeCategory.CLOUD_RESOURCE,
            account_id,
            {"provider": provider, "kind": "cloud-account", "account_id": account_id},
        )

    async def _service_node(
        self, provider: str, account_id: str, service_id: str, properties: dict[str, Any]
    ) -> str | None:
        return await self.upsert_node(
            NodeCategory.AI_SERVICE,
            f"{provider}:{account_id}:{service_id}",
            {"provider": provider, "account_id": account_id, **properties},
        )

    async def _model_node(self, provider: str, account_id: str, model_id: str) -> str | None:
        return await self.upsert_node(
            NodeCategory.AI_MODEL,
            f"{provider}:{account_id}:model:{model_id}",
            {"provider": provider, "name": model_id},
        )

    async def _internet_node(self) -> str | None:
        return await self.upsert_node(
            NodeCategory.CLOUD_RESOURCE, _INTERNET_EXTERNAL_ID, {"kind": "internet"}
        )

    async def _bridge(self, account_node: str | None, service_node: str | None) -> None:
        await self.add_edge(account_node or "", service_node or "", EdgeType.HOSTS_AI)

    async def record_aws(self, inventory: AwsAiInventory) -> None:
        """SageMaker + Bedrock → AI_SERVICE/AI_MODEL nodes + HOSTS_AI/SERVES_MODEL/EXPOSES_MODEL."""
        acct = await self._account_node("aws", inventory.account_id)
        for ep in inventory.sagemaker_endpoints:
            svc = await self._service_node(
                "sagemaker", inventory.account_id, ep.name, {"kind": "endpoint", "name": ep.name}
            )
            await self._bridge(acct, svc)
            if ep.model_name:
                model = await self._model_node("sagemaker", inventory.account_id, ep.model_name)
                await self.add_edge(svc or "", model or "", EdgeType.SERVES_MODEL)
            if ep.network_isolated is False:
                await self.add_edge(
                    svc or "", await self._internet_node() or "", EdgeType.EXPOSES_MODEL
                )
        if inventory.bedrock_logging_enabled is not None:
            bedrock = await self._service_node(
                "bedrock", inventory.account_id, "bedrock", {"kind": "service", "name": "bedrock"}
            )
            await self._bridge(acct, bedrock)

    async def record_azure(self, inventory: AzureAiInventory) -> None:
        """Azure OpenAI accounts → AI_SERVICE nodes + HOSTS_AI/EXPOSES_MODEL."""
        acct = await self._account_node("azure", inventory.subscription_id)
        for account in inventory.accounts:
            svc = await self._service_node(
                "azure_openai",
                inventory.subscription_id,
                account.name,
                {"kind": "openai-account", "name": account.name},
            )
            await self._bridge(acct, svc)
            if account.public_network_access is True:
                await self.add_edge(
                    svc or "", await self._internet_node() or "", EdgeType.EXPOSES_MODEL
                )

    async def record_gcp(self, inventory: GcpAiInventory) -> None:
        """Vertex endpoints → AI_SERVICE nodes + HOSTS_AI/EXPOSES_MODEL."""
        acct = await self._account_node("gcp", inventory.project_id)
        for ep in inventory.endpoints:
            svc = await self._service_node(
                "vertex", inventory.project_id, ep.name, {"kind": "endpoint", "name": ep.name}
            )
            await self._bridge(acct, svc)
            if ep.public is True:
                await self.add_edge(
                    svc or "", await self._internet_node() or "", EdgeType.EXPOSES_MODEL
                )


__all__ = ["KnowledgeGraphWriter"]
