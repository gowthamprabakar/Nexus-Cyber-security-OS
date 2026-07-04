"""FastAPI surface for the auth + tenant flow.

Wires the four routes the F.4 plan calls for:

- `GET  /auth/login`    — 302 redirect to the Auth0 hosted-login URL.
- `GET  /auth/callback` — exchanges the Auth0 code for tokens and
  drops the access token into an HttpOnly session cookie.
- `GET  /auth/me`       — returns the verified JWT claims as JSON.
- `GET  /tenants/me`    — returns the caller's tenant row.
- `POST /tenants`       — admin-only; creates an Auth0 org + a `tenants` row.

Charter audit instrumentation (Task 10) is a deliberate hook this task
leaves open: every handler calls `audit_emit(...)` so Task 10 wiring is
a one-line swap of the callable. v0.1 ships a no-op default so this
task remains self-contained.

The factory takes its dependencies explicitly rather than relying on
module globals — that's what makes the SCIM tests + the auth tests
share the same aiosqlite engine without dance.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

from control_plane.auth.auth0_client import Auth0Client
from control_plane.auth.jwt_verifier import VerifiedToken
from control_plane.auth.mfa import MfaRequiredError, require_mfa, requires_mfa_for
from control_plane.auth.rbac import Action, permission_for
from control_plane.tenants.models import Role, TenantRow

SESSION_COOKIE_NAME = "nexus_session"

VerifyToken = Callable[[str], Awaitable[VerifiedToken]]
AuditEmit = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class Auth0Settings:
    """Static config for the Auth0 OAuth2 dance — supplied by the app builder."""

    domain: str
    client_id: str
    client_secret: str
    audience: str
    redirect_uri: str


class CreateTenantBody(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    display_name: str | None = None


async def _noop_audit(_: str, __: dict[str, Any]) -> None:
    return None


def make_auth_router(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    verify_token: VerifyToken,
    auth0_client: Auth0Client,
    auth0_settings: Auth0Settings,
    audit_emit: AuditEmit = _noop_audit,
) -> APIRouter:
    router = APIRouter(tags=["auth", "tenants"])

    async def current_token(request: Request) -> VerifiedToken:
        token = _extract_token(request)
        try:
            return await verify_token(token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"invalid token: {e}") from e

    # ---------------------------- /auth/login -------------------------

    @router.get("/auth/login")
    async def login() -> RedirectResponse:
        await audit_emit("auth.login.initiated", {})
        params = urlencode(
            {
                "response_type": "code",
                "client_id": auth0_settings.client_id,
                "redirect_uri": auth0_settings.redirect_uri,
                "scope": "openid profile email",
                "audience": auth0_settings.audience,
            }
        )
        return RedirectResponse(
            f"https://{auth0_settings.domain}/authorize?{params}",
            status_code=status.HTTP_302_FOUND,
        )

    # ---------------------------- /auth/callback ----------------------

    @router.get("/auth/callback")
    async def callback(code: str) -> Response:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"https://{auth0_settings.domain}/oauth/token",
                    json={
                        "grant_type": "authorization_code",
                        "client_id": auth0_settings.client_id,
                        "client_secret": auth0_settings.client_secret,
                        "code": code,
                        "redirect_uri": auth0_settings.redirect_uri,
                    },
                )
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"auth0 unreachable: {e}") from e

        if response.status_code != 200:
            await audit_emit("auth.callback.failed", {"status": response.status_code})
            raise HTTPException(status_code=401, detail="token exchange failed")

        body = response.json()
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise HTTPException(status_code=401, detail="auth0 returned no access_token")

        await audit_emit("auth.callback.success", {})
        out = JSONResponse({"status": "logged_in"})
        out.set_cookie(
            SESSION_COOKIE_NAME,
            access_token,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        return out

    # ---------------------------- /auth/me ----------------------------

    _CurrentToken = Depends(current_token)

    @router.get("/auth/me")
    async def me(verified: VerifiedToken = _CurrentToken) -> dict[str, Any]:
        return {
            "sub": verified.sub,
            "tenant_id": verified.tenant_id,
            "roles": list(verified.roles),
            "amr": list(verified.amr),
            "expires_at": verified.expires_at.isoformat(),
        }

    # ---------------------------- /tenants/me -------------------------

    @router.get("/tenants/me")
    async def get_my_tenant(verified: VerifiedToken = _CurrentToken) -> dict[str, Any]:
        async with session_factory() as session:
            tenant = await session.get(TenantRow, verified.tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return tenant.to_pydantic().model_dump(mode="json")

    # ---------------------------- POST /tenants -----------------------

    @router.post("/tenants", status_code=201)
    async def create_tenant(
        body: CreateTenantBody,
        verified: VerifiedToken = _CurrentToken,
    ) -> dict[str, Any]:
        if not _has_admin_action(verified.roles, Action.MANAGE_TENANT):
            raise HTTPException(status_code=403, detail="admin role required")
        if requires_mfa_for(Action.MANAGE_TENANT):
            try:
                require_mfa(verified)
            except MfaRequiredError as e:
                await audit_emit(
                    "mfa_required_failure",
                    {"sub": verified.sub, "action": Action.MANAGE_TENANT.value},
                )
                raise HTTPException(status_code=403, detail=str(e)) from e

        org = await auth0_client.create_organization(name=body.name, display_name=body.display_name)

        tenant_id = str(ULID())
        async with session_factory() as session:
            session.add(
                TenantRow(
                    tenant_id=tenant_id,
                    name=body.name,
                    auth0_org_id=org.id,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()

        await audit_emit(
            "tenant.created",
            {"tenant_id": tenant_id, "actor": verified.sub, "auth0_org_id": org.id},
        )
        return {"tenant_id": tenant_id, "auth0_org_id": org.id, "name": body.name}

    return router


def build_auth_app(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    verify_token: VerifyToken,
    auth0_client: Auth0Client,
    auth0_settings: Auth0Settings,
    audit_emit: AuditEmit = _noop_audit,
) -> FastAPI:
    app = FastAPI(title="Nexus Control Plane — auth")
    app.include_router(
        make_auth_router(
            session_factory=session_factory,
            verify_token=verify_token,
            auth0_client=auth0_client,
            auth0_settings=auth0_settings,
            audit_emit=audit_emit,
        )
    )
    return app


# ---------------------------- helpers -----------------------------------


def _extract_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer ") :].strip()
        if token:
            return token
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie:
        return cookie
    raise HTTPException(status_code=401, detail="missing bearer token or session cookie")


def _has_admin_action(token_roles: tuple[str, ...], action: Action) -> bool:
    for raw in token_roles:
        try:
            if permission_for(Role(raw), action):
                return True
        except ValueError:
            continue
    return False


__all__ = [
    "SESSION_COOKIE_NAME",
    "Auth0Settings",
    "CreateTenantBody",
    "build_auth_app",
    "make_auth_router",
]
