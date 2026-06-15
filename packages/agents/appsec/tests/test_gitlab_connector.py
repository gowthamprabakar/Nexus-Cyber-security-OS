"""GitLab SCM connector tests (D.14 B-1 PR7) — mocked transport, no network."""

from __future__ import annotations

import httpx
import pytest
from appsec.tools.gitlab_connector import GitLabScmConnector
from appsec.tools.scm_connector import ScmConnector

pytestmark = pytest.mark.asyncio


def _project(name: str, *, visibility: str = "private") -> dict[str, object]:
    return {
        "path": name,
        "namespace": {"path": "acme", "full_path": "acme"},
        "http_url_to_repo": f"https://gitlab.com/acme/{name}.git",
        "default_branch": "main",
        "visibility": visibility,
    }


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler, base_url="https://gitlab.com")


async def test_is_an_scm_connector() -> None:
    assert isinstance(GitLabScmConnector(), ScmConnector)


async def test_lists_projects_membership() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v4/projects"
        assert request.url.params.get("membership") == "true"
        return httpx.Response(200, json=[_project("api"), _project("web", visibility="public")])

    repos = await GitLabScmConnector(
        client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert [r.slug for r in repos] == ["gitlab/acme/api", "gitlab/acme/web"]
    assert repos[0].visibility == "private"
    assert repos[1].visibility == "public"
    assert repos[0].clone_url == "https://gitlab.com/acme/api.git"


async def test_group_path_used_when_group_set() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # raw_path preserves the %2F encoding GitLab requires for group paths
        # (request.url.path would decode it).
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json=[])

    await GitLabScmConnector(
        group="acme/platform", client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert seen[0].startswith("/api/v4/groups/acme%2Fplatform/projects")


async def test_follows_link_pagination() -> None:
    page2 = "https://gitlab.com/api/v4/projects?page=2"

    def handler(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            return httpx.Response(200, json=[_project("two")])
        return httpx.Response(
            200, json=[_project("one")], headers={"link": f'<{page2}>; rel="next"'}
        )

    repos = await GitLabScmConnector(
        client=_client(httpx.MockTransport(handler))
    ).list_repositories()
    assert {r.name for r in repos} == {"one", "two"}


async def test_http_error_propagates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "forbidden"})

    with pytest.raises(httpx.HTTPStatusError):
        await GitLabScmConnector(client=_client(httpx.MockTransport(handler))).list_repositories()
