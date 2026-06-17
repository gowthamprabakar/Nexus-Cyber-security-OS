"""Slack posture rules (D.10 SSPM PR4).

Evaluates a typed :class:`~sspm.tools.slack.SlackWorkspaceInventory` into OCSF 2003
findings — 5 real posture checks. Honest tri-state: a ``None`` (unexposed) value never
produces a finding. ``finding_id`` follows ``SSPM-SLACK-<NNN>-<context>``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sspm.schemas import SaaSAffectedResource, SaaSFinding, Severity, build_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from sspm.tools.slack import SlackWorkspaceInventory

#: Slack OAuth scopes that grant broad workspace access — a high-privilege app.
RISKY_SLACK_SCOPES = frozenset(
    {
        "admin",
        "admin.users:write",
        "admin.apps:write",
        "channels:write",
        "groups:write",
        "files:write",
        "users:read.email",
    }
)
DEFAULT_MAX_OWNERS = 3
DEFAULT_MAX_ADMINS = 5


class SlackFindingType(StrEnum):
    MEMBERS_WITHOUT_2FA = "sspm_slack_members_without_2fa"
    EXCESSIVE_OWNERS = "sspm_slack_excessive_owners"
    EXCESSIVE_ADMINS = "sspm_slack_excessive_admins"
    EXTERNAL_GUESTS = "sspm_slack_external_guests"
    HIGH_PRIVILEGE_OAUTH_APP = "sspm_slack_high_privilege_oauth_app"


def _ctx(*parts: str) -> str:
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "workspace"


def _tenant_resource(team_id: str) -> SaaSAffectedResource:
    return SaaSAffectedResource(
        provider="slack", tenant_id=team_id, resource_type="saas_tenant", resource_id=team_id
    )


def evaluate_slack_workspace(
    inventory: SlackWorkspaceInventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
    max_owners: int = DEFAULT_MAX_OWNERS,
    max_admins: int = DEFAULT_MAX_ADMINS,
) -> list[SaaSFinding]:
    """Run the 5 Slack posture checks over the typed inventory."""
    out: list[SaaSFinding] = []
    team = inventory.team_id or "workspace"
    tctx = _ctx(team)
    tres = [_tenant_resource(team)]

    def _add(n: str, rule: str, ft: SlackFindingType, sev: Severity, title: str, desc: str) -> None:
        out.append(
            build_finding(
                finding_id=f"SSPM-SLACK-{n}-{tctx}",
                rule_id=rule,
                finding_type=ft,
                severity=sev,
                title=title,
                description=desc,
                affected=tres,
                detected_at=detected_at,
                envelope=envelope,
            )
        )

    if inventory.members_without_2fa is not None and inventory.members_without_2fa > 0:
        _add(
            "001",
            "SLACK-MEMBER-2FA",
            SlackFindingType.MEMBERS_WITHOUT_2FA,
            Severity.HIGH,
            "Slack workspace has members without two-factor authentication",
            f"Workspace {team} has {inventory.members_without_2fa} active members without 2FA.",
        )
    if inventory.owners > max_owners:
        _add(
            "002",
            "SLACK-OWNERS",
            SlackFindingType.EXCESSIVE_OWNERS,
            Severity.MEDIUM,
            "Slack workspace has an excessive number of owners",
            f"Workspace {team} has {inventory.owners} owners (> {max_owners}).",
        )
    if inventory.admins > max_admins:
        _add(
            "003",
            "SLACK-ADMINS",
            SlackFindingType.EXCESSIVE_ADMINS,
            Severity.MEDIUM,
            "Slack workspace has an excessive number of admins",
            f"Workspace {team} has {inventory.admins} admins (> {max_admins}).",
        )
    if inventory.guests > 0:
        _add(
            "004",
            "SLACK-GUESTS",
            SlackFindingType.EXTERNAL_GUESTS,
            Severity.LOW,
            "Slack workspace has external guest accounts",
            f"Workspace {team} has {inventory.guests} guest (restricted) accounts.",
        )

    for app in inventory.oauth_apps:
        risky = sorted(set(app.scopes) & RISKY_SLACK_SCOPES)
        if not risky:
            continue
        out.append(
            build_finding(
                finding_id=f"SSPM-SLACK-005-{_ctx(team, app.app_id)}",
                rule_id="SLACK-OAUTH-APP",
                finding_type=SlackFindingType.HIGH_PRIVILEGE_OAUTH_APP,
                severity=Severity.HIGH,
                title="Slack OAuth app holds high-privilege scopes",
                description=(
                    f"App {app.name or app.app_id} in workspace {team} holds "
                    f"high-privilege scopes: {', '.join(risky)}."
                ),
                affected=[
                    SaaSAffectedResource(
                        provider="slack",
                        tenant_id=team,
                        resource_type="oauth_app",
                        resource_id=app.app_id,
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    return out


__all__ = ["RISKY_SLACK_SCOPES", "SlackFindingType", "evaluate_slack_workspace"]
