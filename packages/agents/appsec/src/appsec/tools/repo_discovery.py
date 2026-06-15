"""Repository discovery — the charter-registered AppSec discovery tool (D.14 v0.1).

Thin wrapper over an injected ``ScmConnector``: lists repositories, de-duplicates
by slug, and returns them in stable slug order so runs are deterministic.
"""

from __future__ import annotations

from appsec.schemas import RepoRef
from appsec.tools.scm_connector import ScmConnector


async def discover_repositories(*, connector: ScmConnector) -> tuple[RepoRef, ...]:
    """Discover repositories via the connector, de-duped + stably ordered by slug."""
    repos = await connector.list_repositories()
    by_slug: dict[str, RepoRef] = {}
    for repo in repos:
        by_slug.setdefault(repo.slug, repo)
    return tuple(sorted(by_slug.values(), key=lambda r: r.slug))
