"""Live Bitbucket SCM connector (D.14, B-1 PR7; Q-AppSec-2).

Mirrors the GitHub/GitLab connectors against the Bitbucket Cloud REST v2 API via
httpx, authed with the Pattern-A ``ScmCredentialResolver`` (Bearer access token,
resolved at call time, never stored). Lists the caller's member repositories
(``/2.0/repositories?role=member``) or a workspace's repos
(``/2.0/repositories/{workspace}``), follows Bitbucket's body-level ``next``
pagination cursor, and maps each to a ``RepoRef``.

Testable without network via an injected ``httpx.AsyncClient`` (MockTransport).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from appsec.credentials import ScmCredentialResolver
from appsec.schemas import RepoRef


def _clone_url(raw: dict[str, Any]) -> str:
    """Pick the https clone URL from Bitbucket's ``links.clone`` list."""
    links = raw.get("links")
    clone = links.get("clone") if isinstance(links, dict) else None
    if isinstance(clone, list):
        https = next(
            (c.get("href") for c in clone if isinstance(c, dict) and c.get("name") == "https"),
            None,
        )
        if isinstance(https, str) and https:
            return https
        for entry in clone:  # fall back to any clone href
            if isinstance(entry, dict) and isinstance(entry.get("href"), str):
                return str(entry["href"])
    return ""


def _repo_from_bitbucket(raw: dict[str, Any]) -> RepoRef:
    full_name = str(raw.get("full_name", ""))
    workspace_raw = raw.get("workspace")
    workspace = workspace_raw if isinstance(workspace_raw, dict) else {}
    owner = (
        full_name.split("/")[0] if "/" in full_name else str(workspace.get("slug", ""))
    ) or "unknown"
    name = str(raw.get("name", "")) or (full_name.split("/")[-1] if full_name else "") or "unknown"
    mainbranch_raw = raw.get("mainbranch")
    mainbranch = mainbranch_raw if isinstance(mainbranch_raw, dict) else {}
    return RepoRef(
        host="bitbucket",
        owner=owner,
        name=name,
        clone_url=_clone_url(raw) or f"https://bitbucket.org/{owner}/{name}.git",
        default_branch=str(mainbranch.get("name", "") or "main"),
        visibility="private" if raw.get("is_private") else "public",
    )


class BitbucketScmConnector:
    """List Bitbucket repositories visible to the configured token (Pattern-A)."""

    __slots__ = ("_base_url", "_client", "_per_page", "_resolver", "_workspace")

    def __init__(
        self,
        *,
        resolver: ScmCredentialResolver | None = None,
        workspace: str | None = None,
        client: httpx.AsyncClient | None = None,
        base_url: str = "https://api.bitbucket.org",
        per_page: int = 100,
    ) -> None:
        self._resolver = resolver
        self._workspace = workspace
        self._client = client
        self._base_url = base_url
        self._per_page = per_page

    async def list_repositories(self) -> Sequence[RepoRef]:
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            base_url=self._base_url,
            headers=(self._resolver.auth_headers() if self._resolver else {}),
        )
        try:
            if self._workspace:
                url: str | None = f"/2.0/repositories/{self._workspace}?pagelen={self._per_page}"
            else:
                url = f"/2.0/repositories?role=member&pagelen={self._per_page}"
            repos: list[RepoRef] = []
            while url:
                response = await client.get(url)
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict):
                    break
                values = body.get("values")
                if isinstance(values, list):
                    repos.extend(_repo_from_bitbucket(r) for r in values if isinstance(r, dict))
                # Bitbucket paginates via a full "next" URL in the body (not Link).
                nxt = body.get("next")
                url = nxt if isinstance(nxt, str) and nxt else None
            return repos
        finally:
            if owns_client:
                await client.aclose()
