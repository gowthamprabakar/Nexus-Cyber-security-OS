"""Repo discovery + static connector tests (D.14 v0.1)."""

from __future__ import annotations

import pytest
from appsec.schemas import RepoRef
from appsec.tools.repo_discovery import discover_repositories
from appsec.tools.scm_connector import ScmConnector, StaticScmConnector

pytestmark = pytest.mark.asyncio


def _repo(owner: str, name: str, host: str = "github") -> RepoRef:
    return RepoRef(
        host=host,
        owner=owner,
        name=name,
        clone_url=f"https://{host}.com/{owner}/{name}.git",
    )


async def test_static_connector_is_an_scm_connector() -> None:
    assert isinstance(StaticScmConnector(), ScmConnector)


async def test_discovery_empty_by_default() -> None:
    assert await discover_repositories(connector=StaticScmConnector()) == ()


async def test_discovery_dedupes_and_sorts_by_slug() -> None:
    connector = StaticScmConnector(
        [
            _repo("acme", "zeta"),
            _repo("acme", "alpha"),
            _repo("acme", "alpha"),  # duplicate slug
        ]
    )
    repos = await discover_repositories(connector=connector)
    assert [r.slug for r in repos] == ["github/acme/alpha", "github/acme/zeta"]


async def test_repo_slug_shape() -> None:
    assert _repo("acme", "alpha").slug == "github/acme/alpha"
