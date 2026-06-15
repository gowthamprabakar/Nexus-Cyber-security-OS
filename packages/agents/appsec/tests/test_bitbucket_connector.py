"""Bitbucket SCM connector tests (D.14 B-1 PR7) — mocked transport, no network."""

from __future__ import annotations

import httpx
import pytest
from appsec.tools.bitbucket_connector import BitbucketScmConnector
from appsec.tools.scm_connector import ScmConnector

pytestmark = pytest.mark.asyncio


def _repo(name: str, *, private: bool = True) -> dict[str, object]:
    return {
        "full_name": f"acme/{name}",
        "name": name,
        "workspace": {"slug": "acme"},
        "mainbranch": {"name": "main"},
        "is_private": private,
        "links": {
            "clone": [
                {"name": "https", "href": f"https://bitbucket.org/acme/{name}.git"},
                {"name": "ssh", "href": f"git@bitbucket.org:acme/{name}.git"},
            ]
        },
    }


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler, base_url="https://api.bitbucket.org")


async def test_is_an_scm_connector() -> None:
    assert isinstance(BitbucketScmConnector(), ScmConnector)


async def test_lists_repos_picks_https_clone() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/2.0/repositories"
        return httpx.Response(200, json={"values": [_repo("api"), _repo("web", private=False)]})

    repos = await BitbucketScmConnector(
        client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert [r.slug for r in repos] == ["bitbucket/acme/api", "bitbucket/acme/web"]
    assert repos[0].clone_url == "https://bitbucket.org/acme/api.git"  # https, not ssh
    assert repos[0].visibility == "private"
    assert repos[1].visibility == "public"


async def test_workspace_path_used_when_set() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"values": []})

    await BitbucketScmConnector(
        workspace="acme", client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert seen == ["/2.0/repositories/acme"]


async def test_follows_body_next_pagination() -> None:
    page2 = "https://api.bitbucket.org/2.0/repositories?page=2"

    def handler(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"values": [_repo("two")]})
        return httpx.Response(200, json={"values": [_repo("one")], "next": page2})

    repos = await BitbucketScmConnector(
        client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert {r.name for r in repos} == {"one", "two"}


async def test_http_error_propagates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"type": "error"})

    with pytest.raises(httpx.HTTPStatusError):
        await BitbucketScmConnector(
            client=_client(httpx.MockTransport(handler))
        ).list_repositories()
