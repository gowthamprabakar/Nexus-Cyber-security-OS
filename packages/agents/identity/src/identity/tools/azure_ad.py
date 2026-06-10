"""Azure AD / Entra enumeration via Microsoft Graph (D.2 v0.2 Task 10).

Net-new. Reads the directory's users + groups from Microsoft Graph (v1.0) using a
bearer token from the Task-9 `AzureCredentialResolver` (`DefaultAzureCredential`).

Graph access goes through the small `GraphReader` seam, so the enumeration is
unit-testable without a live tenant; `_HttpGraphReader` is the httpx-backed
implementation (bearer token from azure-identity + `@odata.nextLink` paging).

Per WI-I1 this is a **separate** seam from the AWS IAM tooling — Azure AD coverage is
measured on its own, never aggregated with AWS.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

from charter.degradation import degraded_marker

from identity.credentials_azure import AzureCredentialResolver

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
#: servicePrincipalType for a managed identity (the SP class attackers abuse most).
MANAGED_IDENTITY_SP_TYPE = "ManagedIdentity"


class AzureAdListingError(RuntimeError):
    """Microsoft Graph returned an error, or the credential/token was invalid."""


@dataclass(frozen=True, slots=True)
class AzureAdUser:
    id: str
    user_principal_name: str
    display_name: str
    account_enabled: bool


@dataclass(frozen=True, slots=True)
class AzureAdGroup:
    id: str
    display_name: str
    security_enabled: bool


@dataclass(frozen=True, slots=True)
class AzureAdServicePrincipal:
    id: str
    app_id: str
    display_name: str
    sp_type: str  # servicePrincipalType: Application / ManagedIdentity / Legacy / SocialIdp
    account_enabled: bool


@dataclass(frozen=True, slots=True)
class AzureAdListing:
    users: tuple[AzureAdUser, ...]
    groups: tuple[AzureAdGroup, ...]
    service_principals: tuple[AzureAdServicePrincipal, ...] = field(default_factory=tuple)
    #: Pattern-E partial-scan markers ({"section": name, "error": <sanitized>}) for
    #: any Graph collection that failed; the other collections still enumerate.
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)

    @property
    def managed_identities(self) -> tuple[AzureAdServicePrincipal, ...]:
        """The subset of service principals that are managed identities
        (`servicePrincipalType == 'ManagedIdentity'`)."""
        return tuple(sp for sp in self.service_principals if sp.sp_type == MANAGED_IDENTITY_SP_TYPE)


class GraphReader(Protocol):
    """A read seam over Microsoft Graph collection endpoints (handles paging)."""

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        """Return every item across all pages of a Graph collection endpoint."""
        ...


async def azure_ad_list_identities(
    *,
    credential_source: str | None = None,
    graph: GraphReader | None = None,
    timeout_sec: float = 60.0,
) -> AzureAdListing:
    """Enumerate Azure AD users + groups via Microsoft Graph.

    `graph` is injectable for testing; in production it defaults to the
    httpx-backed reader authenticated via the `AzureCredentialResolver`.

    Raises:
        AzureAdListingError: on any Graph / transport / credential error.
    """
    reader = graph or _HttpGraphReader.from_resolver(
        AzureCredentialResolver(source=credential_source), timeout_sec=timeout_sec
    )
    degraded: list[dict[str, str]] = []
    users_raw = await _read_section(
        reader, "users", "id,userPrincipalName,displayName,accountEnabled", degraded
    )
    groups_raw = await _read_section(reader, "groups", "id,displayName,securityEnabled", degraded)
    sps_raw = await _read_section(
        reader,
        "servicePrincipals",
        "id,appId,displayName,servicePrincipalType,accountEnabled",
        degraded,
    )

    # A single denied/failed collection degrades that section (Pattern E) and the
    # scan continues. If EVERY section failed, that is a total failure (e.g. a bad
    # credential) — raise instead of returning an empty "all-degraded" listing.
    if degraded and not (users_raw or groups_raw or sps_raw):
        raise AzureAdListingError(
            f"azure_ad_list_identities failed: all {len(degraded)} Graph collections degraded"
        )

    return AzureAdListing(
        users=tuple(_parse_user(u) for u in users_raw),
        groups=tuple(_parse_group(g) for g in groups_raw),
        service_principals=tuple(_parse_service_principal(s) for s in sps_raw),
        degraded=tuple(degraded),
    )


def build_graph_reader(
    *, credential_source: str | None = None, timeout_sec: float = 60.0
) -> GraphReader:
    """The production httpx-backed `GraphReader`, authenticated via the
    `AzureCredentialResolver`. Other Azure-AD tools (e.g. federation detection)
    reuse this instead of re-deriving the reader."""
    return _HttpGraphReader.from_resolver(
        AzureCredentialResolver(source=credential_source), timeout_sec=timeout_sec
    )


async def _read_section(
    reader: GraphReader, resource: str, select: str, degraded: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Read one Graph collection; on failure record a secret-free Pattern-E marker
    and return [] so the other collections still enumerate."""
    try:
        return await reader.get_all(resource, select=select)
    except Exception as exc:
        degraded.append(degraded_marker("section", resource, exc))
        return []


def _parse_user(u: dict[str, Any]) -> AzureAdUser:
    return AzureAdUser(
        id=str(u.get("id", "")),
        user_principal_name=str(u.get("userPrincipalName", "")),
        display_name=str(u.get("displayName", "")),
        account_enabled=bool(u.get("accountEnabled", False)),
    )


def _parse_group(g: dict[str, Any]) -> AzureAdGroup:
    return AzureAdGroup(
        id=str(g.get("id", "")),
        display_name=str(g.get("displayName", "")),
        security_enabled=bool(g.get("securityEnabled", False)),
    )


def _parse_service_principal(s: dict[str, Any]) -> AzureAdServicePrincipal:
    return AzureAdServicePrincipal(
        id=str(s.get("id", "")),
        app_id=str(s.get("appId", "")),
        display_name=str(s.get("displayName", "")),
        sp_type=str(s.get("servicePrincipalType", "")),
        account_enabled=bool(s.get("accountEnabled", False)),
    )


class _HttpGraphReader:
    """httpx-backed `GraphReader`: bearer token from azure-identity + nextLink paging."""

    def __init__(
        self,
        token_provider: Any,
        *,
        base_url: str = GRAPH_BASE,
        timeout_sec: float = 60.0,
    ) -> None:
        self._token_provider = token_provider
        self._base_url = base_url
        self._timeout = timeout_sec

    @classmethod
    def from_resolver(
        cls, resolver: AzureCredentialResolver, *, timeout_sec: float = 60.0
    ) -> _HttpGraphReader:
        def _token() -> str:
            return str(resolver.resolve_credential().get_token(GRAPH_SCOPE).token)

        return cls(_token, timeout_sec=timeout_sec)

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        import httpx

        token = await asyncio.to_thread(self._token_provider)
        headers = {"Authorization": f"Bearer {token}"}
        url: str | None = f"{self._base_url}/{resource}"
        params: dict[str, str] | None = {"$select": select} if select else None
        items: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            while url:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code >= 400:
                    raise AzureAdListingError(
                        f"Microsoft Graph /{resource} returned HTTP {resp.status_code}"
                    )
                body = resp.json()
                items.extend(body.get("value", []))
                url = body.get("@odata.nextLink")
                params = None  # the nextLink already encodes the query
        return items
