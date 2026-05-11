"""Tests for `control_plane.api.auth_routes` (F.4 Task 8).

`verify_token` and `auth0_client.create_organization` are injected as
fakes — the JWT-verifier crypto and the Auth0 management-API have their
own test files; this suite focuses on routing, dependency wiring,
admin gating, and the OAuth code-exchange dance.

Auth0's `/oauth/token` endpoint is stubbed via respx for the
`/auth/callback` happy + sad paths.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest_asyncio
import respx
from control_plane.api.auth_routes import (
    SESSION_COOKIE_NAME,
    Auth0Settings,
    build_auth_app,
)
from control_plane.auth.auth0_client import Auth0Client, Auth0Organization
from control_plane.auth.jwt_verifier import JwtVerificationError, VerifiedToken
from control_plane.tenants.models import Base, TenantRow
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from ulid import ULID

AUTH0_DOMAIN = "test-tenant.auth0.com"
AUDIENCE = "https://api.nexus.app"
REDIRECT_URI = "https://api.nexus.app/auth/callback"
TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"
TENANT_ID = str(ULID())


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(TenantRow(tenant_id=TENANT_ID, name="Acme", created_at=datetime.now(UTC)))
        await session.commit()
    yield factory
    await engine.dispose()


def _admin_token() -> VerifiedToken:
    return VerifiedToken(
        sub="auth0|admin",
        tenant_id=TENANT_ID,
        roles=("admin",),
        expires_at=datetime.now(UTC),
        amr=("pwd", "mfa"),
    )


def _auditor_token() -> VerifiedToken:
    return VerifiedToken(
        sub="auth0|auditor",
        tenant_id=TENANT_ID,
        roles=("auditor",),
        expires_at=datetime.now(UTC),
        amr=("pwd",),
    )


class _FakeAuth0Client(Auth0Client):
    """Replaces network-bound Auth0Client with an in-memory stub."""

    def __init__(self) -> None:
        super().__init__(
            domain=AUTH0_DOMAIN,
            client_id="cid",
            client_secret="cs",  # noqa: S106 — synthetic test value
        )
        self.created_orgs: list[tuple[str, str | None]] = []

    async def create_organization(
        self,
        *,
        name: str,
        display_name: str | None = None,
    ) -> Auth0Organization:
        self.created_orgs.append((name, display_name))
        return Auth0Organization(id=f"org_{name}", name=name, display_name=display_name)


def _settings() -> Auth0Settings:
    return Auth0Settings(
        domain=AUTH0_DOMAIN,
        client_id="cid",
        client_secret="cs",  # noqa: S106 — synthetic test value
        audience=AUDIENCE,
        redirect_uri=REDIRECT_URI,
    )


def _make_client(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    token: VerifiedToken | None = None,
    raise_on_verify: bool = False,
    auth0_client: Auth0Client | None = None,
) -> tuple[TestClient, _FakeAuth0Client]:
    fake_auth0 = auth0_client or _FakeAuth0Client()

    async def verify(token_str: str) -> VerifiedToken:
        if raise_on_verify:
            raise JwtVerificationError("forced reject")
        if token is None:
            raise JwtVerificationError("no token configured")
        return token

    app = build_auth_app(
        session_factory=session_factory,
        verify_token=verify,
        auth0_client=fake_auth0,
        auth0_settings=_settings(),
    )
    return TestClient(app, follow_redirects=False), fake_auth0  # type: ignore[return-value]


# ---------------------------- /auth/login --------------------------------


def test_login_redirects_to_auth0(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    response = client.get("/auth/login")
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"https://{AUTH0_DOMAIN}/authorize?")
    assert "client_id=cid" in location
    assert "audience=" in location
    assert "scope=openid+profile+email" in location


# ---------------------------- /auth/callback -----------------------------


def test_callback_sets_session_cookie_on_success(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    with respx.mock() as respx_mock:
        respx_mock.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "tok-abc", "token_type": "Bearer", "expires_in": 3600},
            )
        )
        response = client.get("/auth/callback?code=auth-code-xyz")

    assert response.status_code == 200
    cookies = response.headers.get("set-cookie", "")
    assert f"{SESSION_COOKIE_NAME}=tok-abc" in cookies
    assert "HttpOnly" in cookies


def test_callback_returns_401_when_auth0_rejects_code(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    with respx.mock() as respx_mock:
        respx_mock.post(TOKEN_URL).mock(return_value=httpx.Response(403))
        response = client.get("/auth/callback?code=bad-code")

    assert response.status_code == 401


def test_callback_returns_401_when_auth0_omits_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    with respx.mock() as respx_mock:
        respx_mock.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={}))
        response = client.get("/auth/callback?code=ok-but-empty")
    assert response.status_code == 401


# ---------------------------- /auth/me -----------------------------------


def test_me_returns_claims_with_bearer_header(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory, token=_admin_token())
    response = client.get("/auth/me", headers={"authorization": "Bearer tok-abc"})
    assert response.status_code == 200
    body = response.json()
    assert body["sub"] == "auth0|admin"
    assert body["tenant_id"] == TENANT_ID
    assert "admin" in body["roles"]


def test_me_reads_token_from_session_cookie(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory, token=_admin_token())
    client.cookies.set(SESSION_COOKIE_NAME, "tok-from-cookie")
    response = client.get("/auth/me")
    assert response.status_code == 200


def test_me_returns_401_without_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_returns_401_on_invalid_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory, raise_on_verify=True)
    response = client.get("/auth/me", headers={"authorization": "Bearer junk"})
    assert response.status_code == 401


# ---------------------------- /tenants/me --------------------------------


def test_tenants_me_returns_tenant(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory, token=_admin_token())
    response = client.get("/tenants/me", headers={"authorization": "Bearer tok-abc"})
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == TENANT_ID
    assert body["name"] == "Acme"


def test_tenants_me_returns_404_when_token_tenant_missing(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    unknown_token = VerifiedToken(
        sub="auth0|ghost",
        tenant_id=str(ULID()),
        roles=("admin",),
        expires_at=datetime.now(UTC),
        amr=(),
    )
    client, _ = _make_client(session_factory, token=unknown_token)
    response = client.get("/tenants/me", headers={"authorization": "Bearer tok-abc"})
    assert response.status_code == 404


# ---------------------------- POST /tenants ------------------------------


def test_post_tenants_creates_row_and_calls_auth0_mgmt(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, fake_auth0 = _make_client(session_factory, token=_admin_token())
    response = client.post(
        "/tenants",
        json={"name": "globex", "display_name": "Globex Corp"},
        headers={"authorization": "Bearer tok-abc"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "globex"
    assert body["auth0_org_id"] == "org_globex"
    assert len(body["tenant_id"]) == 26
    assert ("globex", "Globex Corp") in fake_auth0.created_orgs


def test_post_tenants_returns_403_for_non_admin(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, fake_auth0 = _make_client(session_factory, token=_auditor_token())
    response = client.post(
        "/tenants",
        json={"name": "globex"},
        headers={"authorization": "Bearer tok-abc"},
    )
    assert response.status_code == 403
    assert fake_auth0.created_orgs == []


def test_post_tenants_returns_401_without_token(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory)
    response = client.post("/tenants", json={"name": "globex"})
    assert response.status_code == 401


def test_post_tenants_rejects_empty_name(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    client, _ = _make_client(session_factory, token=_admin_token())
    response = client.post(
        "/tenants", json={"name": ""}, headers={"authorization": "Bearer tok-abc"}
    )
    assert response.status_code == 422  # pydantic min_length=1 violation


# ---------------------------- audit hook ---------------------------------


def test_audit_hook_called_on_login_and_tenant_create(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    captured: list[tuple[str, dict[str, Any]]] = []

    async def capture(event: str, payload: dict[str, Any]) -> None:
        captured.append((event, payload))

    async def verify(_: str) -> VerifiedToken:
        return _admin_token()

    app = build_auth_app(
        session_factory=session_factory,
        verify_token=verify,
        auth0_client=_FakeAuth0Client(),
        auth0_settings=_settings(),
        audit_emit=capture,
    )
    client = TestClient(app, follow_redirects=False)

    client.get("/auth/login")
    client.post(
        "/tenants",
        json={"name": "newco"},
        headers={"authorization": "Bearer tok-abc"},
    )

    event_names = [e for e, _ in captured]
    assert "auth.login.initiated" in event_names
    assert "tenant.created" in event_names
