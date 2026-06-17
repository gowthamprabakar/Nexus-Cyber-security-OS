"""Tests for the GitHub-org connector (D.10 SSPM PR2).

Real connector logic over a deterministic ``_FakeHttp`` transport (the threat-intel
Protocol+fake pattern) — no live GitHub. Covers org/repo parsing, branch-protection
tri-state, pagination, and PAT auth wiring (token from the resolver, never persisted).
"""

from __future__ import annotations

from typing import Any

import pytest
from sspm.credentials import SaaSCredentialResolver
from sspm.tools.github_org import GITHUB_API, GitHubApiError, read_github_org

pytestmark = pytest.mark.asyncio

_TOKEN_ENV = "NEXUS_SSPM_GITHUB_TOKEN"


class _FakeHttp:
    """A url-keyed HttpTransport fake. Routes: url -> (status, headers, body)."""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], Any]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        self.calls.append((url, headers))
        return self.routes.get(url, (404, {}, None))


def _resolver() -> SaaSCredentialResolver:
    return SaaSCredentialResolver(provider="github", env={"token": _TOKEN_ENV})


def _routes_two_repos() -> dict[str, tuple[int, dict[str, str], Any]]:
    return {
        f"{GITHUB_API}/orgs/acme": (
            200,
            {},
            {
                "two_factor_requirement_enabled": False,
                "default_repository_permission": "admin",
                "members_can_create_public_repositories": True,
            },
        ),
        f"{GITHUB_API}/orgs/acme/repos?per_page=100": (
            200,
            {},
            [
                {
                    "name": "web",
                    "private": False,
                    "default_branch": "main",
                    "security_and_analysis": {
                        "secret_scanning": {"status": "disabled"},
                        "secret_scanning_push_protection": {"status": "disabled"},
                        "dependabot_security_updates": {"status": "enabled"},
                    },
                },
                {
                    "name": "api",
                    "private": True,
                    "default_branch": "main",
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                },
            ],
        ),
        f"{GITHUB_API}/repos/acme/web/branches/main/protection": (404, {}, None),
        f"{GITHUB_API}/repos/acme/api/branches/main/protection": (200, {}, {}),
    }


async def test_reads_org_and_repos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "ghp_test_token")
    http = _FakeHttp(_routes_two_repos())

    inv = await read_github_org(org="acme", resolver=_resolver(), transport=http)

    assert inv.org == "acme"
    assert inv.two_factor_required is False
    assert inv.default_repository_permission == "admin"
    assert inv.members_can_create_public_repos is True

    repos = {r.name: r for r in inv.repos}
    assert set(repos) == {"web", "api"}
    assert repos["web"].private is False
    assert repos["web"].secret_scanning == "disabled"
    assert repos["web"].default_branch_protected is False  # 404 → unprotected
    assert repos["api"].private is True
    assert repos["api"].secret_scanning == "enabled"
    assert repos["api"].default_branch_protected is True  # 200 → protected
    # security fields absent on api → "unknown" (honest tri-state, not "disabled").
    assert repos["api"].dependabot_security_updates == "unknown"


async def test_pat_is_sent_as_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "ghp_test_token")
    http = _FakeHttp(_routes_two_repos())
    await read_github_org(org="acme", resolver=_resolver(), transport=http)
    # Every call carries the resolved PAT as a Bearer header (auth wiring).
    org_call = next(h for u, h in http.calls if u.endswith("/orgs/acme"))
    assert org_call is not None
    assert org_call["Authorization"] == "Bearer ghp_test_token"


async def test_branch_protection_403_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "ghp_test_token")
    routes = {
        f"{GITHUB_API}/orgs/acme": (200, {}, {"two_factor_requirement_enabled": True}),
        f"{GITHUB_API}/orgs/acme/repos?per_page=100": (
            200,
            {},
            [{"name": "x", "private": True, "default_branch": "main"}],
        ),
        f"{GITHUB_API}/repos/acme/x/branches/main/protection": (403, {}, None),
    }
    inv = await read_github_org(org="acme", resolver=_resolver(), transport=_FakeHttp(routes))
    assert inv.repos[0].default_branch_protected is None  # 403 → unknown, not False


async def test_pagination_follows_link_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "ghp_test_token")
    page1 = f"{GITHUB_API}/orgs/acme/repos?per_page=100"
    page2 = f"{GITHUB_API}/orgs/acme/repos?per_page=100&page=2"
    routes = {
        f"{GITHUB_API}/orgs/acme": (200, {}, {"two_factor_requirement_enabled": True}),
        page1: (200, {"Link": f'<{page2}>; rel="next"'}, [{"name": "r1", "private": True}]),
        page2: (200, {}, [{"name": "r2", "private": True}]),
        f"{GITHUB_API}/repos/acme/r1/branches/main/protection": (404, {}, None),
        f"{GITHUB_API}/repos/acme/r2/branches/main/protection": (404, {}, None),
    }
    inv = await read_github_org(org="acme", resolver=_resolver(), transport=_FakeHttp(routes))
    assert {r.name for r in inv.repos} == {"r1", "r2"}


async def test_org_404_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "ghp_test_token")
    http = _FakeHttp({f"{GITHUB_API}/orgs/ghost": (404, {}, None)})
    with pytest.raises(GitHubApiError, match="HTTP 404"):
        await read_github_org(org="ghost", resolver=_resolver(), transport=http)
