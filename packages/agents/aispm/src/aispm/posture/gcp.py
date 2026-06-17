"""GCP Vertex AI posture rules (D.11 AI-SPM PR3).

Evaluates a typed :class:`~aispm.tools.gcp_ai.GcpAiInventory` into OCSF 2003 findings —
3 checks. Honest tri-state: ``None`` (unknown) never flags. ``finding_id``
``AISPM-VERTEX-<NNN>-<context>``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from aispm.schemas import AiAffectedResource, AiFinding, Severity, build_posture_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from aispm.tools.gcp_ai import GcpAiInventory


class GcpAiFindingType(StrEnum):
    ENDPOINT_PUBLIC = "aispm_vertex_endpoint_public"
    ENDPOINT_NO_CMK = "aispm_vertex_endpoint_no_cmk"
    ENDPOINT_NO_PSC = "aispm_vertex_endpoint_no_private_service_connect"


def _ctx(*parts: str) -> str:
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "endpoint"


def evaluate_gcp_ai(
    inventory: GcpAiInventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[AiFinding]:
    """Run the 3 Vertex AI posture checks over the typed inventory."""
    out: list[AiFinding] = []
    project = inventory.project_id

    def _add(
        ep: str, n: str, rule: str, ft: GcpAiFindingType, sev: Severity, title: str, desc: str
    ) -> None:
        out.append(
            build_posture_finding(
                finding_id=f"AISPM-VERTEX-{n}-{_ctx(project, ep)}",
                rule_id=rule,
                finding_type=ft,
                severity=sev,
                title=title,
                description=desc,
                affected=[
                    AiAffectedResource(
                        provider="vertex",
                        account_id=project,
                        resource_type="ai_service",
                        resource_id=ep,
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )

    for ep in inventory.endpoints:
        if ep.public is True:
            _add(
                ep.name,
                "001",
                "AISPM-VX-PUBLIC",
                GcpAiFindingType.ENDPOINT_PUBLIC,
                Severity.HIGH,
                "Vertex AI endpoint has no VPC network (publicly reachable)",
                f"Endpoint {ep.name} in project {project} is not attached to a VPC.",
            )
        if ep.cmk_encrypted is False:
            _add(
                ep.name,
                "002",
                "AISPM-VX-CMK",
                GcpAiFindingType.ENDPOINT_NO_CMK,
                Severity.LOW,
                "Vertex AI endpoint is not encrypted with a customer-managed key",
                f"Endpoint {ep.name} in project {project} uses a Google-managed key.",
            )
        if ep.psc_enabled is False:
            _add(
                ep.name,
                "003",
                "AISPM-VX-PSC",
                GcpAiFindingType.ENDPOINT_NO_PSC,
                Severity.MEDIUM,
                "Vertex AI endpoint has no Private Service Connect",
                f"Endpoint {ep.name} in project {project} has PSC disabled.",
            )
    return out


__all__ = ["GcpAiFindingType", "evaluate_gcp_ai"]
