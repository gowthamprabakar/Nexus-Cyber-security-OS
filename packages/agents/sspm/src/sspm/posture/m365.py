"""Microsoft 365 posture rules (D.10 SSPM PR3).

Evaluates a typed :class:`~sspm.tools.m365.M365Inventory` into OCSF 2003 findings — 6 real
posture checks. Honest tri-state: a ``None`` (unreadable) value NEVER produces a finding.
``finding_id`` follows ``SSPM-M365-<NNN>-<context>``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sspm.schemas import SaaSAffectedResource, SaaSFinding, Severity, build_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from sspm.tools.m365 import M365Inventory

#: OAuth delegated scopes that grant broad tenant access — a high-privilege grant.
RISKY_OAUTH_SCOPES = frozenset(
    {
        "Directory.ReadWrite.All",
        "Directory.Read.All",
        "Mail.Read",
        "Mail.ReadWrite",
        "Files.ReadWrite.All",
        "User.ReadWrite.All",
        "Application.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
    }
)
#: Default ceiling on Global Administrators before it's flagged (CIS-aligned guidance).
DEFAULT_MAX_GLOBAL_ADMINS = 5


class M365FindingType(StrEnum):
    SECURITY_DEFAULTS_DISABLED = "sspm_m365_security_defaults_disabled"
    NO_CONDITIONAL_ACCESS = "sspm_m365_no_conditional_access"
    GUEST_INVITES_UNRESTRICTED = "sspm_m365_guest_invites_unrestricted"
    USER_CONSENT_ALLOWED = "sspm_m365_user_consent_allowed"
    EXCESSIVE_GLOBAL_ADMINS = "sspm_m365_excessive_global_admins"
    HIGH_PRIVILEGE_OAUTH_GRANT = "sspm_m365_high_privilege_oauth_grant"


def _ctx(*parts: str) -> str:
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "tenant"


def _tenant_resource(tenant: str) -> SaaSAffectedResource:
    return SaaSAffectedResource(
        provider="m365", tenant_id=tenant, resource_type="saas_tenant", resource_id=tenant
    )


def evaluate_m365_tenant(
    inventory: M365Inventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
    max_global_admins: int = DEFAULT_MAX_GLOBAL_ADMINS,
) -> list[SaaSFinding]:
    """Run the 6 M365 posture checks over the typed inventory."""
    out: list[SaaSFinding] = []
    tenant = inventory.tenant_id
    tctx = _ctx(tenant)
    tres = [_tenant_resource(tenant)]

    def _add(n: str, rule: str, ft: M365FindingType, sev: Severity, title: str, desc: str) -> None:
        out.append(
            build_finding(
                finding_id=f"SSPM-M365-{n}-{tctx}",
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

    if inventory.security_defaults_enabled is False:  # None → skip
        _add(
            "001",
            "M365-SECURITY-DEFAULTS",
            M365FindingType.SECURITY_DEFAULTS_DISABLED,
            Severity.HIGH,
            "M365 security defaults are disabled",
            f"Tenant {tenant} has security defaults turned off.",
        )
    if inventory.conditional_access_policy_count == 0:
        _add(
            "002",
            "M365-CONDITIONAL-ACCESS",
            M365FindingType.NO_CONDITIONAL_ACCESS,
            Severity.MEDIUM,
            "M365 tenant has no conditional-access policies",
            f"Tenant {tenant} has zero conditional-access policies configured.",
        )
    if inventory.allow_invites_from == "everyone":
        _add(
            "003",
            "M365-GUEST-INVITES",
            M365FindingType.GUEST_INVITES_UNRESTRICTED,
            Severity.MEDIUM,
            "M365 guest invitations are unrestricted",
            f"Tenant {tenant} allows anyone to invite guests.",
        )
    if inventory.user_consent_allowed is True:  # None → skip
        _add(
            "004",
            "M365-USER-CONSENT",
            M365FindingType.USER_CONSENT_ALLOWED,
            Severity.MEDIUM,
            "M365 users can consent to third-party apps",
            f"Tenant {tenant} permits end-user consent to OAuth apps.",
        )
    if (
        inventory.global_admin_count is not None
        and inventory.global_admin_count > max_global_admins
    ):
        _add(
            "005",
            "M365-GLOBAL-ADMINS",
            M365FindingType.EXCESSIVE_GLOBAL_ADMINS,
            Severity.MEDIUM,
            "M365 tenant has an excessive number of Global Administrators",
            f"Tenant {tenant} has {inventory.global_admin_count} Global Admins "
            f"(> {max_global_admins}).",
        )

    for grant in inventory.oauth_grants:
        risky = sorted(set(grant.scopes) & RISKY_OAUTH_SCOPES)
        if not risky:
            continue
        out.append(
            build_finding(
                finding_id=f"SSPM-M365-006-{_ctx(tenant, grant.client_id)}",
                rule_id="M365-OAUTH-GRANT",
                finding_type=M365FindingType.HIGH_PRIVILEGE_OAUTH_GRANT,
                severity=Severity.HIGH,
                title="M365 OAuth app holds a high-privilege grant",
                description=(
                    f"OAuth client {grant.client_id} in tenant {tenant} is granted "
                    f"high-privilege scopes: {', '.join(risky)}."
                ),
                affected=[
                    SaaSAffectedResource(
                        provider="m365",
                        tenant_id=tenant,
                        resource_type="oauth_app",
                        resource_id=grant.client_id,
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    return out


__all__ = ["RISKY_OAUTH_SCOPES", "M365FindingType", "evaluate_m365_tenant"]
