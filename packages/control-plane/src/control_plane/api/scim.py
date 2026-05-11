"""SCIM 2.0 User endpoint — materialize Auth0 webhook provisioning.

Auth0's SCIM 2.0 connector POSTs user resources here; we mirror them
into the `users` table. HMAC-SHA256 over the raw request body
authenticates every call. The secret is per-deployment in v0.1; per-tenant
rotation lands in Phase 1c alongside the tenant-admin console.

The v0.1 endpoint set is intentionally minimal — Auth0's SCIM client
exercises POST / GET / PATCH (active flag) / DELETE. We deliberately do
**not** implement search, paging, or PATCH paths beyond the `active`
flag; everything else is out of scope until a real customer asks.

Nexus extension: `urn:ietf:params:scim:schemas:extension:nexus:2.0:User`
carries `tenantId` (ULID) and an optional `role` (admin / operator /
auditor). The tenant must already exist or the create fails with 404.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

from control_plane.tenants.models import Role, TenantRow, UserRow

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
NEXUS_EXTENSION_SCHEMA = "urn:ietf:params:scim:schemas:extension:nexus:2.0:User"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SIGNATURE_HEADER = "x-scim-signature"


# ---------------------------- factory + app builder ----------------------


def make_scim_router(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    hmac_secret: bytes,
) -> APIRouter:
    """Build a SCIM router bound to a session factory + HMAC secret."""
    router = APIRouter(prefix="/scim/v2", tags=["scim"])

    async def verify_hmac(request: Request) -> bytes:
        body = await request.body()
        header_value = request.headers.get(SIGNATURE_HEADER, "")
        expected = "sha256=" + hmac.new(hmac_secret, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(header_value, expected):
            raise HTTPException(status_code=401, detail="invalid SCIM signature")
        return body

    @router.post("/Users", status_code=201)
    async def create_user(
        body: bytes = Depends(verify_hmac),
    ) -> JSONResponse:
        payload = _decode_json(body)
        scim = _parse_scim_user(payload)
        async with session_factory() as session:
            tenant = await session.get(TenantRow, scim.tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail=f"unknown tenant_id: {scim.tenant_id}")
            user_row = UserRow(
                user_id=str(ULID()),
                auth0_sub=scim.external_id or scim.user_name,
                tenant_id=scim.tenant_id,
                email=scim.user_name,
                role=scim.role.value,
                last_login_at=None,
            )
            session.add(user_row)
            try:
                await session.commit()
            except IntegrityError as e:
                raise HTTPException(status_code=409, detail="user already exists") from e
            await session.refresh(user_row)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=_user_to_scim(user_row),
        )

    @router.get("/Users/{user_id}")
    async def get_user(user_id: str) -> JSONResponse:
        async with session_factory() as session:
            row = await session.get(UserRow, user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="user not found")
        return JSONResponse(content=_user_to_scim(row))

    @router.patch("/Users/{user_id}")
    async def patch_user(user_id: str, body: bytes = Depends(verify_hmac)) -> Response:
        payload = _decode_json(body)
        ops = _parse_patch_ops(payload)
        deactivate = any(
            op.get("op", "").lower() == "replace"
            and op.get("path", "").lower() == "active"
            and op.get("value") is False
            for op in ops
        )
        async with session_factory() as session:
            row = await session.get(UserRow, user_id)
            if row is None:
                raise HTTPException(status_code=404, detail="user not found")
            if deactivate:
                await session.delete(row)
                await session.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.delete("/Users/{user_id}", status_code=204)
    async def delete_user(user_id: str, _: bytes = Depends(verify_hmac)) -> Response:
        async with session_factory() as session:
            row = await session.get(UserRow, user_id)
            if row is None:
                raise HTTPException(status_code=404, detail="user not found")
            await session.delete(row)
            await session.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router


def build_scim_app(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    hmac_secret: bytes,
) -> FastAPI:
    app = FastAPI(title="Nexus SCIM 2.0")
    app.include_router(make_scim_router(session_factory=session_factory, hmac_secret=hmac_secret))
    return app


def sign_body(body: bytes, secret: bytes) -> str:
    """Helper exposed for callers (and tests) that need to mint signatures."""
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


# ---------------------------- parse / shape helpers ----------------------


class _ParsedScimUser:
    __slots__ = ("active", "external_id", "role", "tenant_id", "user_name")

    def __init__(
        self,
        *,
        user_name: str,
        external_id: str | None,
        active: bool,
        tenant_id: str,
        role: Role,
    ) -> None:
        self.user_name = user_name
        self.external_id = external_id
        self.active = active
        self.tenant_id = tenant_id
        self.role = role


def _decode_json(body: bytes) -> dict[str, Any]:
    import json

    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="SCIM payload must be an object")
    return payload


def _parse_scim_user(payload: dict[str, Any]) -> _ParsedScimUser:
    schemas = payload.get("schemas") or []
    if SCIM_USER_SCHEMA not in schemas:
        raise HTTPException(
            status_code=400,
            detail=f"payload missing required schema: {SCIM_USER_SCHEMA}",
        )

    user_name = payload.get("userName")
    if not isinstance(user_name, str) or not user_name:
        raise HTTPException(status_code=400, detail="userName is required")

    external_id = payload.get("externalId") if isinstance(payload.get("externalId"), str) else None
    active = bool(payload.get("active", True))

    extension = payload.get(NEXUS_EXTENSION_SCHEMA)
    if not isinstance(extension, dict):
        raise HTTPException(
            status_code=400,
            detail=f"required extension missing: {NEXUS_EXTENSION_SCHEMA}",
        )
    tenant_id = extension.get("tenantId")
    if not isinstance(tenant_id, str) or len(tenant_id) != 26:
        raise HTTPException(status_code=400, detail="extension.tenantId must be a 26-char ULID")
    role_raw = extension.get("role", "auditor")
    try:
        role = Role(role_raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"unknown role: {role_raw!r}") from e

    return _ParsedScimUser(
        user_name=user_name,
        external_id=external_id,
        active=active,
        tenant_id=tenant_id,
        role=role,
    )


def _parse_patch_ops(payload: dict[str, Any]) -> list[dict[str, Any]]:
    schemas = payload.get("schemas") or []
    if PATCH_OP_SCHEMA not in schemas:
        raise HTTPException(
            status_code=400,
            detail=f"PATCH payload missing required schema: {PATCH_OP_SCHEMA}",
        )
    ops = payload.get("Operations")
    if not isinstance(ops, list):
        raise HTTPException(status_code=400, detail="Operations must be a list")
    return [op for op in ops if isinstance(op, dict)]


def _user_to_scim(row: UserRow) -> dict[str, Any]:
    """Render a UserRow back into a SCIM 2.0 User document."""
    now_iso = datetime.now(UTC).isoformat()
    return {
        "schemas": [SCIM_USER_SCHEMA, NEXUS_EXTENSION_SCHEMA],
        "id": row.user_id,
        "externalId": row.auth0_sub,
        "userName": row.email,
        "active": True,
        "emails": [{"value": row.email, "primary": True}],
        "meta": {
            "resourceType": "User",
            "created": now_iso,
            "lastModified": now_iso,
            "location": f"/scim/v2/Users/{row.user_id}",
        },
        NEXUS_EXTENSION_SCHEMA: {
            "tenantId": row.tenant_id,
            "role": row.role,
        },
    }


async def _load_user_or_404(session: AsyncSession, user_id: str) -> UserRow:
    row = await session.get(UserRow, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    # mypy nudge — we returned above otherwise.
    _ = await session.execute(select(UserRow).where(UserRow.user_id == user_id))
    return row


__all__ = [
    "NEXUS_EXTENSION_SCHEMA",
    "PATCH_OP_SCHEMA",
    "SCIM_USER_SCHEMA",
    "SIGNATURE_HEADER",
    "build_scim_app",
    "make_scim_router",
    "sign_body",
]
