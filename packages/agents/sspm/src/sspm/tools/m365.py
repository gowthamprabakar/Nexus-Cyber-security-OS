"""Microsoft 365 SaaS connector (D.10 SSPM PR3, operator Q1 connector #2).

Reads a tenant's security posture from Microsoft Graph into a typed ``M365Inventory`` —
security defaults, guest-invite policy, user-consent policy, conditional-access policy
count, Global Administrator count, and OAuth permission grants.

**Reuse note (vs the brainstorm's "reuse the GraphReader verbatim"):** SSPM reuses the
identity agent's GraphReader *pattern* — a collection seam (``GraphClient``) + fake
injection (the institutional Azure-AD test style) — but NOT its concrete reader, because
that auths via the azure-identity SDK (``DefaultAzureCredential`` chain). Per operator Q3,
SSPM SaaS auth is **OAuth2 client-credentials from env** (``SaaSCredentialResolver``), so
the live ``_HttpGraphClient`` does its own client-credentials token exchange. This keeps
the SSPM package decoupled from the identity package and honors the env-token contract.
Tests inject a fake ``GraphClient`` and never touch auth/httpx.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from sspm.credentials import SaaSCredentialResolver

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
#: Well-known Azure AD Global Administrator role template id.
GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"


class M365ApiError(RuntimeError):
    """A Microsoft Graph call failed (non-2xx, or token exchange failed)."""


class GraphClient(Protocol):
    """Microsoft Graph read seam — collection (``get_all``) + single-object (``get_one``)."""

    async def get_all(
        self, resource: str, *, select: str | None = None
    ) -> list[dict[str, Any]]: ...

    async def get_one(self, resource: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class M365OAuthGrant:
    client_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class M365Inventory:
    tenant_id: str
    security_defaults_enabled: bool | None  # None = not readable
    allow_invites_from: str  # "everyone" | "adminsAndGuestInviters" | ... | "unknown"
    user_consent_allowed: bool | None
    conditional_access_policy_count: int
    global_admin_count: int | None
    oauth_grants: tuple[M365OAuthGrant, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


async def _safe_all(
    graph: GraphClient, resource: str, degraded: list[dict[str, str]]
) -> list[dict[str, Any]]:
    try:
        return await graph.get_all(resource)
    except Exception as exc:  # Pattern-E: degrade this collection, keep scanning.
        degraded.append({"section": resource, "error": exc.__class__.__name__})
        return []


async def _safe_one(
    graph: GraphClient, resource: str, degraded: list[dict[str, str]]
) -> dict[str, Any] | None:
    try:
        return await graph.get_one(resource)
    except Exception as exc:
        degraded.append({"section": resource, "error": exc.__class__.__name__})
        return None


async def read_m365_tenant(
    *,
    tenant_id: str,
    graph: GraphClient,
    max_oauth_grants: int = 200,
) -> M365Inventory:
    """Fetch a tenant's security posture into a typed inventory (tri-state honest)."""
    degraded: list[dict[str, str]] = []

    sd = await _safe_one(graph, "policies/identitySecurityDefaultsEnforcementPolicy", degraded)
    auth = await _safe_one(graph, "policies/authorizationPolicy", degraded)

    allow_invites_from = "unknown"
    user_consent_allowed: bool | None = None
    if auth is not None:
        allow_invites_from = str(auth.get("allowInvitesFrom", "unknown"))
        dur = auth.get("defaultUserRolePermissions")
        if isinstance(dur, dict):
            user_consent_allowed = bool(dur.get("permissionGrantPoliciesAssigned"))

    ca = await _safe_all(graph, "identity/conditionalAccessPolicies", degraded)

    global_admin_count: int | None = None
    roles = await _safe_all(graph, "directoryRoles", degraded)
    ga_role = next(
        (
            r
            for r in roles
            if r.get("roleTemplateId") == GLOBAL_ADMIN_TEMPLATE_ID
            or r.get("displayName") == "Global Administrator"
        ),
        None,
    )
    if ga_role and ga_role.get("id"):
        members = await _safe_all(graph, f"directoryRoles/{ga_role['id']}/members", degraded)
        global_admin_count = len(members)

    grants_raw = await _safe_all(graph, "oauth2PermissionGrants", degraded)
    grants = tuple(
        M365OAuthGrant(
            client_id=str(g.get("clientId", "")),
            scopes=tuple(str(g.get("scope") or "").split()),
        )
        for g in grants_raw[:max_oauth_grants]
        if g.get("clientId")
    )

    return M365Inventory(
        tenant_id=tenant_id,
        security_defaults_enabled=(bool(sd.get("isEnabled")) if sd is not None else None),
        allow_invites_from=allow_invites_from,
        user_consent_allowed=user_consent_allowed,
        conditional_access_policy_count=len(ca),
        global_admin_count=global_admin_count,
        oauth_grants=grants,
        degraded=tuple(degraded),
    )


class _HttpGraphClient:
    """Live httpx-backed GraphClient: OAuth2 client-credentials token + nextLink paging."""

    def __init__(
        self, resolver: SaaSCredentialResolver, tenant_id: str, *, timeout_sec: float = 30.0
    ) -> None:
        self._resolver = resolver
        self._tenant_id = tenant_id
        self._timeout = timeout_sec

    async def _token(self) -> str:
        import httpx

        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._resolver.resolve("client_id"),
            "client_secret": self._resolver.resolve("client_secret"),  # never persisted
            "scope": "https://graph.microsoft.com/.default",
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, data=data)
        if resp.status_code >= 400:
            raise M365ApiError(f"token exchange returned HTTP {resp.status_code}")
        return str(resp.json().get("access_token", ""))

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        import httpx

        token = await self._token()
        headers = {"Authorization": f"Bearer {token}"}
        url: str | None = f"{GRAPH_BASE}/{resource}"
        params: dict[str, str] | None = {"$select": select} if select else None
        items: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            while url:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code >= 400:
                    raise M365ApiError(f"Graph /{resource} returned HTTP {resp.status_code}")
                body = resp.json()
                items.extend(body.get("value", []))
                url = body.get("@odata.nextLink")
                params = None
        return items

    async def get_one(self, resource: str) -> dict[str, Any]:
        import httpx

        token = await self._token()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(f"{GRAPH_BASE}/{resource}", headers=headers)
        if resp.status_code >= 400:
            raise M365ApiError(f"Graph /{resource} returned HTTP {resp.status_code}")
        body = resp.json()
        return body if isinstance(body, dict) else {}


def build_graph_client(resolver: SaaSCredentialResolver, tenant_id: str) -> GraphClient:
    """The live httpx-backed GraphClient (NEXUS_LIVE path)."""
    return _HttpGraphClient(resolver, tenant_id)


__all__ = [
    "GLOBAL_ADMIN_TEMPLATE_ID",
    "GraphClient",
    "M365ApiError",
    "M365Inventory",
    "M365OAuthGrant",
    "build_graph_client",
    "read_m365_tenant",
]
