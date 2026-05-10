"""Tenant, User, Role models — Phase 1a tenant table.

Per [F.4 plan Task 2](../../../../../docs/superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md#task-2)
and Q3 (RBAC model) resolution: three hard-coded roles
(admin / operator / auditor) for v0.1; DB-backed permissions land in
Phase 1c when finer-grained per-customer roles are needed.

Two parallel model representations:

- **Pydantic** — for the API surface (FastAPI request / response shapes,
  JSON I/O, validation at the boundary).
- **SQLAlchemy** — for persistence (asyncpg / Postgres). Names mirror
  the pydantic models suffixed with `Row` to keep the line clear.

The first alembic migration is the canonical schema for Phase 1a.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Role(StrEnum):
    """The three Phase-1 roles. Custom roles deferred to Phase 1c."""

    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


# ---------------------------- pydantic (API surface) ---------------------


class Tenant(BaseModel):
    """A customer tenancy. ULID-keyed; Auth0 org id is nullable until SAML is provisioned."""

    tenant_id: str = Field(min_length=26, max_length=26)  # ULID
    name: str = Field(min_length=1, max_length=255)
    auth0_org_id: str | None = None
    created_at: datetime
    suspended_at: datetime | None = None

    model_config = ConfigDict(frozen=True)


class User(BaseModel):
    """An authenticated user. `auth0_sub` is the JWT `sub` claim — the canonical IdP key."""

    user_id: str = Field(min_length=26, max_length=26)  # ULID
    auth0_sub: str = Field(min_length=1)
    tenant_id: str = Field(min_length=26, max_length=26)
    email: EmailStr
    role: Role
    last_login_at: datetime | None = None

    model_config = ConfigDict(frozen=True)


# ---------------------------- SQLAlchemy (persistence) -------------------


class Base(DeclarativeBase):
    """Declarative base for all control-plane tables."""


class TenantRow(Base):
    """`tenants` table. ULID PK; Auth0 org id is nullable + unique when set."""

    __tablename__ = "tenants"

    tenant_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth0_org_id: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    users: Mapped[list[UserRow]] = relationship(back_populates="tenant")

    def to_pydantic(self) -> Tenant:
        return Tenant(
            tenant_id=self.tenant_id,
            name=self.name,
            auth0_org_id=self.auth0_org_id,
            created_at=self.created_at,
            suspended_at=self.suspended_at,
        )


class UserRow(Base):
    """`users` table. `auth0_sub` is the IdP-canonical key; ULID PK is internal."""

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    auth0_sub: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[TenantRow] = relationship(back_populates="users")

    def to_pydantic(self) -> User:
        return User(
            user_id=self.user_id,
            auth0_sub=self.auth0_sub,
            tenant_id=self.tenant_id,
            email=self.email,
            role=Role(self.role),
            last_login_at=self.last_login_at,
        )
