"""Tests for `control_plane.auth.auth0_client.Auth0Client`.

Uses respx to mock the Auth0 management API. Covers:
- Management-token fetch + per-instance caching.
- invite_user / list_users / create_organization happy paths.
- 4xx error mapping into `Auth0Error.status_code`.
- 5xx + 429 retry (succeed after transient failures; exhaust → raise).
"""

from __future__ import annotations

import httpx
import pytest
import respx
from control_plane.auth.auth0_client import (
    Auth0Client,
    Auth0Error,
    Auth0Organization,
    Auth0User,
)

DOMAIN = "test-tenant.auth0.com"


def _client() -> Auth0Client:
    return Auth0Client(
        domain=DOMAIN,
        client_id="test-cid",
        client_secret="test-secret",  # noqa: S106 — synthetic value for unit tests
    )


def _mock_token(respx_mock: respx.Router, *, ttl: int = 86400) -> respx.Route:
    return respx_mock.post(f"https://{DOMAIN}/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "tok-abc", "expires_in": ttl, "token_type": "Bearer"},
        )
    )


# ---------------------------- token caching ------------------------------


@pytest.mark.asyncio
async def test_management_token_cached_across_calls() -> None:
    """Two calls in one client should fetch the token only once."""
    async with respx.mock() as respx_mock:
        token_route = _mock_token(respx_mock)
        users_route = respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            return_value=httpx.Response(200, json=[])
        )
        client = _client()
        await client.list_users()
        await client.list_users()

    assert token_route.call_count == 1
    assert users_route.call_count == 2


# ---------------------------- invite_user --------------------------------


@pytest.mark.asyncio
async def test_invite_user_happy_path() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        respx_mock.post(f"https://{DOMAIN}/api/v2/users").mock(
            return_value=httpx.Response(
                201,
                json={
                    "user_id": "auth0|123",
                    "email": "alice@example.com",
                    "blocked": False,
                    "app_metadata": {"tenant_id": "01HXYZ"},
                },
            )
        )
        user = await _client().invite_user(
            email="alice@example.com",
            app_metadata={"tenant_id": "01HXYZ"},
        )

    assert isinstance(user, Auth0User)
    assert user.email == "alice@example.com"
    assert user.user_id == "auth0|123"
    assert user.app_metadata == {"tenant_id": "01HXYZ"}


@pytest.mark.asyncio
async def test_invite_user_400_maps_to_auth0_error() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        respx_mock.post(f"https://{DOMAIN}/api/v2/users").mock(
            return_value=httpx.Response(400, text='{"error":"invalid_email"}')
        )
        with pytest.raises(Auth0Error) as excinfo:
            await _client().invite_user(email="bad")

    assert excinfo.value.status_code == 400


# ---------------------------- list_users ---------------------------------


@pytest.mark.asyncio
async def test_list_users_happy_path() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"user_id": "auth0|1", "email": "a@example.com"},
                    {"user_id": "auth0|2", "email": "b@example.com"},
                ],
            )
        )
        users = await _client().list_users()

    assert len(users) == 2
    assert {u.email for u in users} == {"a@example.com", "b@example.com"}


@pytest.mark.asyncio
async def test_list_users_passes_pagination_and_search_query() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        route = respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            return_value=httpx.Response(200, json=[])
        )
        await _client().list_users(page=2, per_page=20, q='email:"alice*"')

    request = route.calls.last.request
    params = dict(request.url.params)
    assert params["page"] == "2"
    assert params["per_page"] == "20"
    assert params["q"] == 'email:"alice*"'
    assert params["search_engine"] == "v3"


# ---------------------------- create_organization ------------------------


@pytest.mark.asyncio
async def test_create_organization_happy_path() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        respx_mock.post(f"https://{DOMAIN}/api/v2/organizations").mock(
            return_value=httpx.Response(
                201, json={"id": "org_abc", "name": "acme", "display_name": "Acme Corp"}
            )
        )
        org = await _client().create_organization(name="acme", display_name="Acme Corp")

    assert isinstance(org, Auth0Organization)
    assert org.id == "org_abc"
    assert org.name == "acme"
    assert org.display_name == "Acme Corp"


# ---------------------------- retry / error mapping ----------------------


@pytest.mark.asyncio
async def test_5xx_retried_then_succeeds() -> None:
    """Two transient 503s then a 200 — third attempt wins."""
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        route = respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(503),
                httpx.Response(200, json=[]),
            ]
        )
        users = await _client().list_users()

    assert users == []
    assert route.call_count == 3


@pytest.mark.asyncio
async def test_5xx_retries_exhausted_raises() -> None:
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(503),
                httpx.Response(503),
            ]
        )
        with pytest.raises(Auth0Error):
            await _client().list_users()


@pytest.mark.asyncio
async def test_429_rate_limit_retried() -> None:
    """Auth0 rate-limit responses (429) are retried like 5xx."""
    async with respx.mock() as respx_mock:
        _mock_token(respx_mock)
        route = respx_mock.get(f"https://{DOMAIN}/api/v2/users").mock(
            side_effect=[httpx.Response(429), httpx.Response(200, json=[])]
        )
        users = await _client().list_users()

    assert users == []
    assert route.call_count == 2


# ---------------------------- token error paths --------------------------


@pytest.mark.asyncio
async def test_oauth_token_4xx_raises_auth0_error() -> None:
    async with respx.mock() as respx_mock:
        respx_mock.post(f"https://{DOMAIN}/oauth/token").mock(
            return_value=httpx.Response(401, text='{"error":"unauthorized"}')
        )
        with pytest.raises(Auth0Error) as excinfo:
            await _client().list_users()

    assert excinfo.value.status_code == 401
