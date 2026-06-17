"""Tests for the Slack connector (D.10 SSPM PR4).

Real connector logic over a deterministic url-keyed ``_FakeHttp`` (the github connector's
HttpTransport seam) — no live Slack. Covers ok/error handling, cursor pagination, 2FA
tri-state, and graceful degradation of the Enterprise-Grid apps endpoint.
"""

from __future__ import annotations

from typing import Any

import pytest
from sspm.credentials import SaaSCredentialResolver
from sspm.tools.slack import SLACK_API, SlackApiError, read_slack_workspace

pytestmark = pytest.mark.asyncio

_TOKEN_ENV = "NEXUS_SSPM_SLACK_TOKEN"


class _FakeHttp:
    def __init__(self, routes: dict[str, tuple[int, dict[str, str], Any]]) -> None:
        self.routes = routes

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        return self.routes.get(url, (404, {}, {"ok": False, "error": "not_found"}))


def _resolver() -> SaaSCredentialResolver:
    return SaaSCredentialResolver(provider="slack", env={"token": _TOKEN_ENV})


def _base_routes() -> dict[str, tuple[int, dict[str, str], Any]]:
    return {
        f"{SLACK_API}/team.info": (200, {}, {"ok": True, "team": {"id": "T01", "name": "Acme"}}),
        f"{SLACK_API}/users.list?limit=200": (
            200,
            {},
            {
                "ok": True,
                "members": [
                    {"id": "U1", "is_owner": True, "is_admin": True, "has_2fa": True},
                    {"id": "U2", "is_admin": True, "has_2fa": False},
                    {"id": "U3", "is_restricted": True, "has_2fa": True},
                    {"id": "B1", "is_bot": True},
                    {"id": "U4", "deleted": True},
                ],
                "response_metadata": {"next_cursor": ""},
            },
        ),
        f"{SLACK_API}/admin.apps.approved.list?limit=100": (
            200,
            {},
            {
                "ok": True,
                "approved_apps": [
                    {"app": {"id": "A1", "name": "Risky"}, "scopes": ["admin", "chat:write"]},
                    {"app": {"id": "A2", "name": "Safe"}, "scopes": ["chat:write"]},
                ],
            },
        ),
    }


async def test_reads_workspace_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "xoxb-test")
    inv = await read_slack_workspace(resolver=_resolver(), transport=_FakeHttp(_base_routes()))

    assert inv.team_id == "T01"
    assert inv.team_name == "Acme"
    assert inv.owners == 1
    assert inv.admins == 2  # U1 + U2
    assert inv.guests == 1  # U3 restricted
    assert inv.members_without_2fa == 1  # U2 (bots/deleted excluded)
    assert {a.app_id for a in inv.oauth_apps} == {"A1", "A2"}


async def test_2fa_tristate_when_field_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "xoxb-test")
    routes = _base_routes()
    routes[f"{SLACK_API}/users.list?limit=200"] = (
        200,
        {},
        {"ok": True, "members": [{"id": "U1", "is_admin": True}], "response_metadata": {}},
    )
    inv = await read_slack_workspace(resolver=_resolver(), transport=_FakeHttp(routes))
    assert inv.members_without_2fa is None  # has_2fa not exposed → unknown, not 0


async def test_apps_endpoint_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "xoxb-test")
    routes = _base_routes()
    routes[f"{SLACK_API}/admin.apps.approved.list?limit=100"] = (
        200,
        {},
        {"ok": False, "error": "not_an_enterprise_install"},
    )
    inv = await read_slack_workspace(resolver=_resolver(), transport=_FakeHttp(routes))
    assert inv.oauth_apps == ()
    assert any(d["section"] == "admin.apps.approved.list" for d in inv.degraded)


async def test_cursor_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "xoxb-test")
    routes = _base_routes()
    routes[f"{SLACK_API}/users.list?limit=200"] = (
        200,
        {},
        {
            "ok": True,
            "members": [{"id": "U1", "is_owner": True}],
            "response_metadata": {"next_cursor": "c2"},
        },
    )
    routes[f"{SLACK_API}/users.list?limit=200&cursor=c2"] = (
        200,
        {},
        {"ok": True, "members": [{"id": "U2", "is_owner": True}], "response_metadata": {}},
    )
    inv = await read_slack_workspace(resolver=_resolver(), transport=_FakeHttp(routes))
    assert inv.owners == 2


async def test_team_info_not_ok_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "xoxb-test")
    routes = {f"{SLACK_API}/team.info": (200, {}, {"ok": False, "error": "invalid_auth"})}
    with pytest.raises(SlackApiError, match=r"team\.info"):
        await read_slack_workspace(resolver=_resolver(), transport=_FakeHttp(routes))
