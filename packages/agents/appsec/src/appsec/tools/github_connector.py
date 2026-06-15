"""Live GitHub SCM connector (D.14, B-1 PR5; Q-AppSec-2).

Implements the ``ScmConnector`` protocol against the GitHub REST API via httpx,
authenticated with the Pattern-A ``ScmCredentialResolver`` (token resolved at call
time, never stored). Lists repositories for the authenticated user (``/user/repos``)
or an org (``/orgs/{org}/repos``), following the ``Link: rel="next"`` pagination
header, and maps each to a ``RepoRef``.

Testable without network: pass an injected ``httpx.AsyncClient`` (e.g. backed by
``httpx.MockTransport``); when none is given the connector builds its own client
from the resolver's auth headers and closes it. GitLab / Bitbucket connectors
follow the same shape (later PRs).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from appsec.credentials import ScmCredentialResolver
from appsec.schemas import RepoRef


def _repo_from_github(raw: dict[str, Any]) -> RepoRef:
    owner = str((raw.get("owner") or {}).get("login", "")) or "unknown"
    return RepoRef(
        host="github",
        owner=owner,
        name=str(raw.get("name", "")) or "unknown",
        clone_url=str(raw.get("clone_url", "")) or f"https://github.com/{owner}",
        default_branch=str(raw.get("default_branch", "") or "main"),
        visibility="private" if raw.get("private") else "public",
    )


def _next_link(link_header: str) -> str | None:
    """Parse a GitHub ``Link`` header for the ``rel="next"`` URL, if any."""
    for part in link_header.split(","):
        segments = [s.strip() for s in part.split(";")]
        if len(segments) < 2:
            continue
        url = segments[0].strip("<>")
        if any(seg == 'rel="next"' for seg in segments[1:]):
            return url
    return None


class GitHubScmConnector:
    """List GitHub repositories visible to the configured token (Pattern-A)."""

    __slots__ = ("_base_url", "_client", "_org", "_per_page", "_resolver")

    def __init__(
        self,
        *,
        resolver: ScmCredentialResolver | None = None,
        org: str | None = None,
        client: httpx.AsyncClient | None = None,
        base_url: str = "https://api.github.com",
        per_page: int = 100,
    ) -> None:
        self._resolver = resolver
        self._org = org
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
            path = f"/orgs/{self._org}/repos" if self._org else "/user/repos"
            url: str | None = f"{path}?per_page={self._per_page}"
            repos: list[RepoRef] = []
            while url:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, list):
                    repos.extend(_repo_from_github(raw) for raw in payload if isinstance(raw, dict))
                url = _next_link(response.headers.get("link", ""))
            return repos
        finally:
            if owns_client:
                await client.aclose()
