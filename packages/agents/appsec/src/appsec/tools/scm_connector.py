"""SCM connector contract + an offline static connector (D.14 v0.1).

The ``ScmConnector`` Protocol is the seam repo discovery calls. v0.1 ships a
deterministic ``StaticScmConnector`` (an explicit repo list — used for runs without
live SCM and for tests). The live GitHub / GitLab / Bitbucket connectors
(httpx + the Pattern-A resolver's auth headers) land in B-1 PR2.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from appsec.schemas import RepoRef


@runtime_checkable
class ScmConnector(Protocol):
    """Lists repositories visible to the configured SCM credential."""

    async def list_repositories(self) -> Sequence[RepoRef]:
        """Return the repositories this connector can see (no secret material)."""
        ...


class StaticScmConnector:
    """Deterministic connector over an explicit repo list (offline / tests).

    The default v0.1 connector when no live SCM connector is injected — discovery
    is a no-op (empty inventory) rather than a live API call, keeping runs
    deterministic until the live connectors land.
    """

    __slots__ = ("_repositories",)

    def __init__(self, repositories: Iterable[RepoRef] = ()) -> None:
        self._repositories = tuple(repositories)

    async def list_repositories(self) -> Sequence[RepoRef]:
        return self._repositories
