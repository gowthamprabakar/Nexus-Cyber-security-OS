"""SSPM knowledge-graph writer (v0.4 D.10 PR5 — SaaS inventory on the coherent spine).

Consumes the typed connector inventories and writes the SaaS inventory into the fleet
graph as the first consumer of ADR-018's scaffolded SaaS vocabulary:

- ``SAAS_TENANT`` nodes — one per scanned tenant/org/workspace (GitHub org, M365 tenant,
  Slack workspace), keyed ``{provider}:{tenant_id}``.
- ``OAUTH_APP`` nodes — third-party apps authorized in a tenant (M365 OAuth grants, Slack
  approved apps), keyed ``{provider}:{tenant_id}:app:{app_id}``.
- ``AUTHORIZED`` edges — OAuth app → SaaS tenant (the shadow-integration surface).

**Operator Q5 scope:** SAAS_TENANT + OAUTH_APP + AUTHORIZED ship now; SAAS_USER
enumeration is deferred to a follow-up.

**SSO_INTO / FEDERATED_FROM (SaaS → cloud account)** — the cross-domain bridge (D.10's
analogue of D.6's IRSA bridge) needs the *cloud-account target* of a federation/SSO trust,
which the three v0.4 connectors do not yet read. Drawing it would require a
federation-config collection step; it is **surfaced here, not fabricated** — a clean
follow-up (the cloud-account node is owned by the posture agents on the same spine).

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed vocabulary,
within-run dedup, opt-in/inert. Reads the typed inventories, never OCSF findings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

if TYPE_CHECKING:
    from sspm.tools.github_org import GitHubOrgInventory
    from sspm.tools.m365 import M365Inventory
    from sspm.tools.slack import SlackWorkspaceInventory


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists SaaS tenant + OAuth-app nodes and AUTHORIZED edges from connector inventories."""

    async def _tenant_node(self, provider: str, tenant_id: str, name: str) -> str | None:
        return await self.upsert_node(
            NodeCategory.SAAS_TENANT,
            f"{provider}:{tenant_id}",
            {"provider": provider, "tenant_id": tenant_id, "name": name},
        )

    async def _oauth_app(
        self,
        provider: str,
        tenant_id: str,
        tenant_node: str | None,
        app_id: str,
        *,
        name: str,
        scopes: tuple[str, ...],
    ) -> None:
        app_node = await self.upsert_node(
            NodeCategory.OAUTH_APP,
            f"{provider}:{tenant_id}:app:{app_id}",
            {"provider": provider, "name": name, "scopes": list(scopes)},
        )
        await self.add_edge(app_node or "", tenant_node or "", EdgeType.AUTHORIZED)

    async def record_github(self, inventory: GitHubOrgInventory) -> None:
        """GitHub org → SAAS_TENANT node (no OAuth-app inventory in the v0.4 connector)."""
        await self._tenant_node("github", inventory.org, inventory.org)

    async def record_m365(self, inventory: M365Inventory) -> None:
        """M365 tenant → SAAS_TENANT + an OAUTH_APP/AUTHORIZED per OAuth grant."""
        tenant_node = await self._tenant_node("m365", inventory.tenant_id, inventory.tenant_id)
        for grant in inventory.oauth_grants:
            await self._oauth_app(
                "m365",
                inventory.tenant_id,
                tenant_node,
                grant.client_id,
                name=grant.client_id,
                scopes=grant.scopes,
            )

    async def record_slack(self, inventory: SlackWorkspaceInventory) -> None:
        """Slack workspace → SAAS_TENANT + an OAUTH_APP/AUTHORIZED per approved app."""
        tenant_node = await self._tenant_node("slack", inventory.team_id, inventory.team_name)
        for app in inventory.oauth_apps:
            await self._oauth_app(
                "slack",
                inventory.team_id,
                tenant_node,
                app.app_id,
                name=app.name,
                scopes=app.scopes,
            )


__all__ = ["KnowledgeGraphWriter"]
