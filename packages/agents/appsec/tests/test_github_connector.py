"""Live GitHub SCM connector tests (D.14 B-1 PR5) — mocked transport, no network."""

from __future__ import annotations

import json

import httpx
import pytest
from appsec.tools.github_connector import GitHubScmConnector
from appsec.tools.scm_connector import ScmConnector

pytestmark = pytest.mark.asyncio


def _repo_json(name: str, *, private: bool = True) -> dict[str, object]:
    return {
        "name": name,
        "owner": {"login": "acme"},
        "clone_url": f"https://github.com/acme/{name}.git",
        "default_branch": "main",
        "private": private,
    }


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler, base_url="https://api.github.com")


async def test_is_an_scm_connector() -> None:
    assert isinstance(GitHubScmConnector(), ScmConnector)


async def test_lists_repos_single_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user/repos"
        return httpx.Response(200, json=[_repo_json("api"), _repo_json("web", private=False)])

    connector = GitHubScmConnector(client=_client(httpx.MockTransport(handler)))
    repos = await connector.list_repositories()
    assert [r.slug for r in repos] == ["github/acme/api", "github/acme/web"]
    assert repos[0].visibility == "private"
    assert repos[1].visibility == "public"
    assert repos[0].clone_url == "https://github.com/acme/api.git"


async def test_follows_pagination_link() -> None:
    page2 = "https://api.github.com/user/repos?page=2"

    def handler(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            return httpx.Response(200, json=[_repo_json("two")])
        return httpx.Response(
            200,
            json=[_repo_json("one")],
            headers={"link": f'<{page2}>; rel="next"'},
        )

    connector = GitHubScmConnector(client=_client(httpx.MockTransport(handler)))
    repos = await connector.list_repositories()
    assert {r.name for r in repos} == {"one", "two"}


async def test_org_path_used_when_org_set() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json=[])

    connector = GitHubScmConnector(org="acme", client=_client(httpx.MockTransport(handler)))
    await connector.list_repositories()
    assert seen == ["/orgs/acme/repos"]


async def test_http_error_propagates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    connector = GitHubScmConnector(client=_client(httpx.MockTransport(handler)))
    with pytest.raises(httpx.HTTPStatusError):
        await connector.list_repositories()


def test_repo_json_helper_shape() -> None:
    # guard: fixture shape stays a list of dicts (what the API returns)
    assert isinstance(json.loads(json.dumps([_repo_json("x")])), list)
