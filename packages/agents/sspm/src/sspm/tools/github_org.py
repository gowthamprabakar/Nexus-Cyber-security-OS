"""GitHub-org SaaS connector (D.10 SSPM PR2, operator Q1 connector #1).

Reads an organization's security-relevant posture from the GitHub REST API into a typed
``GitHubOrgInventory`` — org-level settings (2FA enforcement, default permission, public-
repo creation) + per-repo settings (visibility, secret scanning, push protection,
Dependabot security updates, default-branch protection). Posture *rules* over this typed
inventory live in :mod:`sspm.posture.github`; this module only fetches + types.

Auth is a PAT via :meth:`SaaSCredentialResolver.bearer_token` — resolved per call into a
transient request header, **never persisted** on any instance (swiss bar). HTTP runs over
an injectable :class:`HttpTransport` seam (the threat-intel pattern) so the connector is
unit-tested with a deterministic fake; the httpx-backed transport is the live path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from sspm.credentials import SaaSCredentialResolver

GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"


class GitHubApiError(RuntimeError):
    """A GitHub API call failed (non-2xx, or an unexpected payload shape)."""


class HttpTransport(Protocol):
    """Async HTTP seam — returns ``(status, headers, body)``; body is JSON-parsed."""

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]: ...


@dataclass(frozen=True, slots=True)
class GitHubRepo:
    name: str
    private: bool
    default_branch: str
    secret_scanning: str  # "enabled" | "disabled" | "unknown"
    secret_scanning_push_protection: str
    dependabot_security_updates: str
    default_branch_protected: bool | None  # None = unknown (not 200/404)


@dataclass(frozen=True, slots=True)
class GitHubOrgInventory:
    org: str
    two_factor_required: bool | None  # None = not visible to the token
    default_repository_permission: str
    members_can_create_public_repos: bool
    repos: tuple[GitHubRepo, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


def _security_status(security_and_analysis: dict[str, Any], key: str) -> str:
    entry = security_and_analysis.get(key)
    if isinstance(entry, dict) and entry.get("status"):
        return str(entry["status"])
    return "unknown"


def _next_link(headers: dict[str, str]) -> str | None:
    """Parse the RFC-5988 ``Link`` header for the ``rel="next"`` URL (GitHub pagination)."""
    link = next((v for k, v in headers.items() if k.lower() == "link"), None)
    if not link:
        return None
    for part in link.split(","):
        segments = part.split(";")
        if len(segments) >= 2 and 'rel="next"' in segments[1]:
            return segments[0].strip().strip("<>")
    return None


async def _paginate(
    transport: HttpTransport, url: str, headers: dict[str, str], *, max_items: int
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url and len(items) < max_items:
        status, resp_headers, body = await transport.get(next_url, headers=headers)
        if status != 200:
            raise GitHubApiError(f"GET {next_url} -> HTTP {status}")
        if isinstance(body, list):
            items.extend(b for b in body if isinstance(b, dict))
        next_url = _next_link(resp_headers)
    return items[:max_items]


async def _branch_protected(
    transport: HttpTransport, org: str, repo: str, branch: str, headers: dict[str, str]
) -> bool | None:
    status, _, _ = await transport.get(
        f"{GITHUB_API}/repos/{org}/{repo}/branches/{branch}/protection", headers=headers
    )
    if status == 200:
        return True
    if status == 404:
        return False
    return None  # 403/other → unknown (don't false-positive)


async def read_github_org(
    *,
    org: str,
    resolver: SaaSCredentialResolver,
    transport: HttpTransport,
    max_repos: int = 100,
) -> GitHubOrgInventory:
    """Fetch an org's security posture into a typed inventory. PAT auth, never persisted."""
    headers = {
        "Authorization": f"Bearer {resolver.bearer_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }
    status, _, org_body = await transport.get(f"{GITHUB_API}/orgs/{org}", headers=headers)
    if status != 200 or not isinstance(org_body, dict):
        raise GitHubApiError(f"GET /orgs/{org} -> HTTP {status}")

    two_factor = org_body.get("two_factor_requirement_enabled")
    repos: list[GitHubRepo] = []
    for raw in await _paginate(
        transport, f"{GITHUB_API}/orgs/{org}/repos?per_page=100", headers, max_items=max_repos
    ):
        name = str(raw.get("name", ""))
        if not name:
            continue
        default_branch = str(raw.get("default_branch") or "main")
        sa = raw.get("security_and_analysis")
        sa = sa if isinstance(sa, dict) else {}
        repos.append(
            GitHubRepo(
                name=name,
                private=bool(raw.get("private", True)),
                default_branch=default_branch,
                secret_scanning=_security_status(sa, "secret_scanning"),
                secret_scanning_push_protection=_security_status(
                    sa, "secret_scanning_push_protection"
                ),
                dependabot_security_updates=_security_status(sa, "dependabot_security_updates"),
                default_branch_protected=await _branch_protected(
                    transport, org, name, default_branch, headers
                ),
            )
        )

    return GitHubOrgInventory(
        org=org,
        two_factor_required=bool(two_factor) if two_factor is not None else None,
        default_repository_permission=str(org_body.get("default_repository_permission", "read")),
        members_can_create_public_repos=bool(
            org_body.get("members_can_create_public_repositories")
        ),
        repos=tuple(repos),
    )


def httpx_transport() -> HttpTransport:
    """The live httpx-backed transport (NEXUS_LIVE path). Builds a client per request."""

    class _Httpx:
        async def get(
            self, url: str, *, headers: dict[str, str] | None = None
        ) -> tuple[int, dict[str, str], Any]:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, headers=headers)
            body: Any = None
            if resp.content:
                try:
                    body = resp.json()
                except ValueError:
                    body = None
            return resp.status_code, dict(resp.headers), body

    return _Httpx()


__all__ = [
    "GITHUB_API",
    "GitHubApiError",
    "GitHubOrgInventory",
    "GitHubRepo",
    "HttpTransport",
    "httpx_transport",
    "read_github_org",
]
