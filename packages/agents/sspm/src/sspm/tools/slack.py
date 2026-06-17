"""Slack SaaS connector (D.10 SSPM PR4, operator Q1 connector #3).

Reads a workspace's security posture from the Slack Web API into a typed
``SlackWorkspaceInventory`` — workspace identity, owner/admin/guest counts, members
without 2FA, and approved OAuth apps. Reuses the GitHub connector's ``HttpTransport``
seam (the threat-intel Protocol+fake pattern). Bearer-token auth via
``SaaSCredentialResolver.bearer_token()`` — resolved per call, never persisted.

Slack Web API responses are ``{"ok": bool, ...}``; ``users.list`` paginates by
``response_metadata.next_cursor``. The approved-apps endpoint (Enterprise-Grid scoped)
degrades gracefully when unavailable (``ok=false``) — recorded, never fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sspm.tools.github_org import HttpTransport  # reuse the get-seam Protocol

if TYPE_CHECKING:
    from sspm.credentials import SaaSCredentialResolver

SLACK_API = "https://slack.com/api"


class SlackApiError(RuntimeError):
    """A Slack Web API call failed (transport error, or ``ok=false`` on a required call)."""


@dataclass(frozen=True, slots=True)
class SlackOAuthApp:
    app_id: str
    name: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SlackWorkspaceInventory:
    team_id: str
    team_name: str
    owners: int
    admins: int
    guests: int
    members_without_2fa: int | None  # None = has_2fa not exposed to this token
    oauth_apps: tuple[SlackOAuthApp, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


def _ok(body: Any) -> bool:
    return isinstance(body, dict) and bool(body.get("ok"))


async def _paginate_members(
    transport: HttpTransport, headers: dict[str, str], *, max_members: int
) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    cursor = ""
    while len(members) < max_members:
        url = f"{SLACK_API}/users.list?limit=200"
        if cursor:
            url += f"&cursor={cursor}"
        status, _, body = await transport.get(url, headers=headers)
        if status != 200 or not _ok(body):
            raise SlackApiError(f"users.list -> HTTP {status} ok={_ok(body)}")
        members.extend(m for m in body.get("members", []) if isinstance(m, dict))
        cursor = (body.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            break
    return members[:max_members]


async def _approved_apps(
    transport: HttpTransport, headers: dict[str, str], degraded: list[dict[str, str]]
) -> tuple[SlackOAuthApp, ...]:
    status, _, body = await transport.get(
        f"{SLACK_API}/admin.apps.approved.list?limit=100", headers=headers
    )
    if status != 200 or not _ok(body):
        # Enterprise-Grid scoped; absent on standard workspaces → degrade, don't fabricate.
        degraded.append({"section": "admin.apps.approved.list", "error": "unavailable"})
        return ()
    apps: list[SlackOAuthApp] = []
    for entry in body.get("approved_apps", []):
        app = entry.get("app") if isinstance(entry, dict) else None
        if not isinstance(app, dict) or not app.get("id"):
            continue
        scopes = entry.get("scopes") or app.get("scopes") or []
        apps.append(
            SlackOAuthApp(
                app_id=str(app["id"]),
                name=str(app.get("name", "")),
                scopes=tuple(str(s) for s in scopes if isinstance(s, str)),
            )
        )
    return tuple(apps)


async def read_slack_workspace(
    *,
    resolver: SaaSCredentialResolver,
    transport: HttpTransport,
    max_members: int = 2000,
) -> SlackWorkspaceInventory:
    """Fetch a workspace's posture into a typed inventory. Bearer auth, never persisted."""
    headers = {"Authorization": f"Bearer {resolver.bearer_token()}"}
    degraded: list[dict[str, str]] = []

    status, _, team_body = await transport.get(f"{SLACK_API}/team.info", headers=headers)
    if status != 200 or not _ok(team_body):
        raise SlackApiError(f"team.info -> HTTP {status} ok={_ok(team_body)}")
    team = team_body.get("team") if isinstance(team_body.get("team"), dict) else {}

    members = await _paginate_members(transport, headers, max_members=max_members)
    humans = [m for m in members if not m.get("is_bot") and not m.get("deleted")]
    has_2fa_exposed = any("has_2fa" in m for m in humans)
    members_without_2fa = (
        sum(1 for m in humans if m.get("has_2fa") is False) if has_2fa_exposed else None
    )

    return SlackWorkspaceInventory(
        team_id=str(team.get("id", "")),
        team_name=str(team.get("name", "")),
        owners=sum(1 for m in members if m.get("is_owner")),
        admins=sum(1 for m in members if m.get("is_admin")),
        guests=sum(1 for m in members if m.get("is_restricted") or m.get("is_ultra_restricted")),
        members_without_2fa=members_without_2fa,
        oauth_apps=await _approved_apps(transport, headers, degraded),
        degraded=tuple(degraded),
    )


__all__ = [
    "SLACK_API",
    "SlackApiError",
    "SlackOAuthApp",
    "SlackWorkspaceInventory",
    "read_slack_workspace",
]
