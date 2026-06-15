"""Live GitLab SCM connector (D.14, B-1 PR7; Q-AppSec-2).

Mirrors the GitHub connector against the GitLab REST v4 API via httpx, authed with
the Pattern-A ``ScmCredentialResolver`` (Bearer token, resolved at call time, never
stored). Lists the caller's member projects (``/api/v4/projects?membership=true``)
or a group's projects (``/api/v4/groups/{group}/projects``), follows the
``Link: rel="next"`` pagination header, and maps each to a ``RepoRef``.

Testable without network via an injected ``httpx.AsyncClient`` (MockTransport).
GitLab.com or self-hosted (``base_url`` override).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

import httpx

from appsec.credentials import ScmCredentialResolver
from appsec.schemas import RepoRef


def _repo_from_gitlab(raw: dict[str, Any]) -> RepoRef:
    namespace_raw = raw.get("namespace")
    namespace = namespace_raw if isinstance(namespace_raw, dict) else {}
    owner = str(namespace.get("full_path") or namespace.get("path") or "") or "unknown"
    name = str(raw.get("path", "")) or "unknown"
    return RepoRef(
        host="gitlab",
        owner=owner,
        name=name,
        clone_url=str(raw.get("http_url_to_repo", "")) or f"https://gitlab.com/{owner}/{name}.git",
        default_branch=str(raw.get("default_branch", "") or "main"),
        visibility=str(raw.get("visibility", "") or "unknown"),
    )


def _next_link(link_header: str) -> str | None:
    """Parse a ``Link`` header for the ``rel="next"`` URL (GitLab + GitHub format)."""
    for part in link_header.split(","):
        segments = [s.strip() for s in part.split(";")]
        if len(segments) < 2:
            continue
        url = segments[0].strip("<>")
        if any(seg == 'rel="next"' for seg in segments[1:]):
            return url
    return None


class GitLabScmConnector:
    """List GitLab projects visible to the configured token (Pattern-A)."""

    __slots__ = ("_base_url", "_client", "_group", "_per_page", "_resolver")

    def __init__(
        self,
        *,
        resolver: ScmCredentialResolver | None = None,
        group: str | None = None,
        client: httpx.AsyncClient | None = None,
        base_url: str = "https://gitlab.com",
        per_page: int = 100,
    ) -> None:
        self._resolver = resolver
        self._group = group
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
            if self._group:
                url: str | None = (
                    f"/api/v4/groups/{quote(self._group, safe='')}/projects"
                    f"?per_page={self._per_page}"
                )
            else:
                url = f"/api/v4/projects?membership=true&per_page={self._per_page}"
            repos: list[RepoRef] = []
            while url:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, list):
                    repos.extend(_repo_from_gitlab(raw) for raw in payload if isinstance(raw, dict))
                url = _next_link(response.headers.get("link", ""))
            return repos
        finally:
            if owns_client:
                await client.aclose()
