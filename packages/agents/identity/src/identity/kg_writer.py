"""Identity knowledge-graph writer (v0.4 Stage 1.2/D.2).

Writes the **IAM principal inventory** the catalogue (#711) assigns Identity into the
fleet graph from the typed ``IdentityListing`` the agent already fetches: users / roles
/ groups as ``IDENTITY`` nodes, customer-managed policies as ``POLICY`` nodes, with
``ATTACHED_TO`` (policy → principal) and ``MEMBER_OF`` (user → group) edges.

What stays out of this writer (by design):

- ``HAS_ACCESS_TO`` (principal → cloud resource) is **cross-agent Stage 3 correlation**
  — the resource side is owned by D.1/D.5/F.3, not the identity listing. Surfaced here,
  not faked.
- Inline policies have no ARN (they are embedded in the principal); their *grants* are
  evaluated for admin detection (#729) but they are not standalone graph nodes.

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed
vocabulary (ADR-018), within-run dedup, opt-in/inert when no store. Offline default
writes nothing → findings.json byte-identical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

if TYPE_CHECKING:
    from collections.abc import Sequence

    from identity.tools.aws_iam import IdentityListing


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists IAM principals + managed policies + attachment/membership edges."""

    async def record_listing(self, listing: IdentityListing) -> None:
        """Upsert principal/policy nodes + ATTACHED_TO / MEMBER_OF edges (deduped)."""
        # Principal nodes (keyed by ARN); track group name → ARN for MEMBER_OF.
        node_ids: dict[str, str | None] = {}
        group_arn_by_name: dict[str, str] = {}

        for user in listing.users:
            node_ids[user.arn] = await self.upsert_node(
                NodeCategory.IDENTITY, user.arn, {"name": user.name, "principal_type": "user"}
            )
        for role in listing.roles:
            node_ids[role.arn] = await self.upsert_node(
                NodeCategory.IDENTITY, role.arn, {"name": role.name, "principal_type": "role"}
            )
        for group in listing.groups:
            node_ids[group.arn] = await self.upsert_node(
                NodeCategory.IDENTITY, group.arn, {"name": group.name, "principal_type": "group"}
            )
            group_arn_by_name[group.name] = group.arn

        # ATTACHED_TO: each attached managed-policy ARN → principal. Policy nodes are
        # upserted on first reference (AWS-managed policies aren't in listing.policies).
        async def _attach(principal_arn: str, policy_arns: tuple[str, ...]) -> None:
            principal_node = node_ids.get(principal_arn)
            for policy_arn in policy_arns:
                policy_node = await self.upsert_node(
                    NodeCategory.POLICY, policy_arn, {"name": policy_arn.rsplit("/", 1)[-1]}
                )
                await self.add_edge(
                    policy_node or "", principal_node or "", EdgeType.ATTACHED_TO, {}
                )

        for user in listing.users:
            await _attach(user.arn, user.attached_policy_arns)
        for role in listing.roles:
            await _attach(role.arn, role.attached_policy_arns)
        for group in listing.groups:
            await _attach(group.arn, group.attached_policy_arns)

        # MEMBER_OF: user → group (group_memberships are names → resolve to ARN).
        for user in listing.users:
            for group_name in user.group_memberships:
                group_arn = group_arn_by_name.get(group_name)
                if group_arn is None:
                    continue
                await self.add_edge(
                    node_ids.get(user.arn) or "",
                    node_ids.get(group_arn) or "",
                    EdgeType.MEMBER_OF,
                    {},
                )

    async def record_access(self, grants: Sequence[tuple[str, str]]) -> None:
        """Write IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE edges (cross-agent spine).

        Each grant is ``(principal_arn, resource_arn)``. Both endpoints are upserted
        idempotently — same ARN ⇒ same spine node cloud-posture/DSPM already own, so
        the edge lands on the shared graph. ``grants`` is computed by the agent driver
        from policy resource statements; the writer only persists.
        """
        for principal_arn, resource_arn in grants:
            principal_node = await self.upsert_node(NodeCategory.IDENTITY, principal_arn, {})
            resource_node = await self.upsert_node(NodeCategory.CLOUD_RESOURCE, resource_arn, {})
            await self.add_edge(
                principal_node or "", resource_node or "", EdgeType.HAS_ACCESS_TO, {}
            )

    async def record_assume_grants(self, grants: Sequence[tuple[str, str]]) -> None:
        """Write IDENTITY --ASSUMES--> IDENTITY edges (internal role assumption, path #13).

        Each grant is ``(assuming_principal_arn, role_arn)``: a same-account principal a role's trust
        policy lets assume it. Both endpoints upserted idempotently onto the IDENTITY spine, so the
        edge joins principals the listing already wrote. The escalation reach (the assumed role's
        ``HAS_ACCESS_TO``) is the privilege-escalation detector's join.
        """
        for principal_arn, role_arn in grants:
            principal_node = await self.upsert_node(NodeCategory.IDENTITY, principal_arn, {})
            role_node = await self.upsert_node(NodeCategory.IDENTITY, role_arn, {})
            await self.add_edge(principal_node or "", role_node or "", EdgeType.ASSUMES, {})

    async def record_escalation_grants(self, grants: Sequence[tuple[str, str, str, str]]) -> None:
        """Write IDENTITY --CAN_ESCALATE_TO--> IDENTITY edges (privilege escalation, slice #1).

        Each grant is ``(principal_arn, target_arn, method, via_action)``: the principal can obtain
        the target admin's privileges via the named technique. ``confidence=confirmed`` — the
        detector only emits when a real admin target is resolved. Both endpoints upserted onto the
        IDENTITY spine; the path engine traverses ``CAN_ESCALATE_TO`` so privilege-escalation-to-data
        paths emerge (and multi-hop chains fall out of single-hop edges via traversal).
        """
        for principal_arn, target_arn, method, via_action in grants:
            principal_node = await self.upsert_node(NodeCategory.IDENTITY, principal_arn, {})
            target_node = await self.upsert_node(NodeCategory.IDENTITY, target_arn, {})
            await self.add_edge(
                principal_node or "",
                target_node or "",
                EdgeType.CAN_ESCALATE_TO,
                {"method": method, "via_action": via_action, "confidence": "confirmed"},
            )

    async def record_credential_ownership(self, grants: Sequence[tuple[str, str]]) -> None:
        """Write IDENTITY --OWNS--> SECRET(access-key-id) for each IAM user access key (path #17).

        Each grant is ``(user_arn, access_key_id)``. The SECRET node is keyed by the access key ID
        (the non-secret identifier), the SAME key appsec uses for a credential leaked in code — so
        the leaked credential and its owning identity converge. No secret material.
        """
        for user_arn, key_id in grants:
            user_node = await self.upsert_node(NodeCategory.IDENTITY, user_arn, {})
            cred_node = await self.upsert_node(
                NodeCategory.SECRET, key_id, {"kind": "aws-access-key"}
            )
            await self.add_edge(user_node or "", cred_node or "", EdgeType.OWNS, {})

    async def record_external_trust(self, principal_arns: Sequence[str]) -> None:
        """Mark IDENTITY principals as externally trusted (path-8 cross-account signal).

        Each ARN is upserted with ``external_trust=True`` — properties merge, so this
        decorates the principal node ``record_listing`` already wrote without dropping
        its name/type. ``principal_arns`` is computed by the agent driver from the offline
        trust-policy analysis (``_externally_trusted_arns``); the writer only persists.
        """
        for principal_arn in principal_arns:
            await self.upsert_node(NodeCategory.IDENTITY, principal_arn, {"external_trust": True})


__all__ = ["KnowledgeGraphWriter"]
