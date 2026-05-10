"""Tenant resolver: maps a verified Auth0 token to (tenant_id, user_id).

First-login provisioning: a token whose `sub` is unknown causes a fresh
`UserRow` to be inserted, tied to the token's `tenant_id` claim. The
caller supplies `email` (sourced from /userinfo or SCIM) because Auth0
access tokens don't always carry it.

Reject paths:
- Token's `tenant_id` claim references no tenant row → `TenantNotFoundError`.
- Tenant row has `suspended_at` set → `TenantSuspendedError`.

Roles: when the JWT carries any role string that matches our `Role` enum
we honor it; otherwise the user is provisioned with `default_role`. The
RBAC table (Task 6) decides what the role can actually do.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

from control_plane.auth.jwt_verifier import VerifiedToken
from control_plane.tenants.models import Role, TenantRow, UserRow


class TenantResolutionError(RuntimeError):
    """Base class for resolver errors."""


class TenantNotFoundError(TenantResolutionError):
    """The token's tenant_id claim does not match any tenant row."""


class TenantSuspendedError(TenantResolutionError):
    """The tenant exists but is suspended; deny access."""


@dataclass(frozen=True, slots=True)
class ResolvedIdentity:
    """Outcome of `TenantResolver.resolve`."""

    tenant_id: str
    user_id: str
    role: Role
    is_first_login: bool


class TenantResolver:
    """Resolve a `VerifiedToken` to an internal user / tenant pair."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def resolve(
        self,
        verified: VerifiedToken,
        *,
        email: str,
        default_role: Role = Role.AUDITOR,
    ) -> ResolvedIdentity:
        async with self._session_factory() as session:
            tenant = await session.get(TenantRow, verified.tenant_id)
            if tenant is None:
                raise TenantNotFoundError(f"unknown tenant_id from token: {verified.tenant_id!r}")
            if tenant.suspended_at is not None:
                raise TenantSuspendedError(
                    f"tenant {verified.tenant_id} suspended at {tenant.suspended_at.isoformat()}"
                )

            existing_q = await session.execute(
                select(UserRow).where(UserRow.auth0_sub == verified.sub)
            )
            existing = existing_q.scalar_one_or_none()
            if existing is not None:
                existing.last_login_at = datetime.now(UTC)
                await session.commit()
                return ResolvedIdentity(
                    tenant_id=existing.tenant_id,
                    user_id=existing.user_id,
                    role=Role(existing.role),
                    is_first_login=False,
                )

            role = _role_from_token(verified, default_role)
            new_user = UserRow(
                user_id=str(ULID()),
                auth0_sub=verified.sub,
                tenant_id=tenant.tenant_id,
                email=email,
                role=role.value,
                last_login_at=datetime.now(UTC),
            )
            session.add(new_user)
            await session.commit()
            return ResolvedIdentity(
                tenant_id=tenant.tenant_id,
                user_id=new_user.user_id,
                role=role,
                is_first_login=True,
            )


def _role_from_token(verified: VerifiedToken, default: Role) -> Role:
    for raw in verified.roles:
        try:
            return Role(raw)
        except ValueError:
            continue
    return default


__all__ = [
    "ResolvedIdentity",
    "TenantNotFoundError",
    "TenantResolutionError",
    "TenantResolver",
    "TenantSuspendedError",
]
