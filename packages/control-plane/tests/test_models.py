"""Tests for `control_plane.tenants.models` — Tenant + User + Role pydantic + SQLAlchemy."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from control_plane.tenants.models import (
    Role,
    Tenant,
    TenantRow,
    User,
    UserRow,
)
from pydantic import ValidationError

_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
_USER_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFA"


# ---------------------------- Role enum ---------------------------------


def test_role_has_three_phase1_values() -> None:
    assert {r.value for r in Role} == {"admin", "operator", "auditor"}


def test_role_round_trip() -> None:
    for r in Role:
        assert Role(r.value) is r


def test_role_rejects_unknown_value() -> None:
    with pytest.raises(ValueError):
        Role("super_admin")


# ---------------------------- Tenant pydantic ---------------------------


def test_tenant_round_trip() -> None:
    now = datetime.now(UTC)
    t = Tenant(
        tenant_id=_ULID,
        name="Acme Corp",
        auth0_org_id=None,
        created_at=now,
    )
    assert t.tenant_id == _ULID
    assert t.suspended_at is None


def test_tenant_rejects_short_id() -> None:
    with pytest.raises(ValidationError):
        Tenant(
            tenant_id="too-short",
            name="Acme",
            auth0_org_id=None,
            created_at=datetime.now(UTC),
        )


def test_tenant_is_frozen() -> None:
    t = Tenant(
        tenant_id=_ULID,
        name="Acme",
        auth0_org_id=None,
        created_at=datetime.now(UTC),
    )
    with pytest.raises((TypeError, ValidationError)):
        t.name = "Hacked"  # type: ignore[misc]


# ---------------------------- User pydantic -----------------------------


def test_user_round_trip() -> None:
    u = User(
        user_id=_USER_ULID,
        auth0_sub="auth0|abc123",
        tenant_id=_ULID,
        email="alice@example.com",
        role=Role.OPERATOR,
    )
    assert u.role is Role.OPERATOR
    assert u.last_login_at is None


def test_user_rejects_invalid_email() -> None:
    with pytest.raises(ValidationError):
        User(
            user_id=_USER_ULID,
            auth0_sub="auth0|abc123",
            tenant_id=_ULID,
            email="not-an-email",
            role=Role.AUDITOR,
        )


def test_user_role_round_trip_via_string() -> None:
    """Pydantic accepts the string form and coerces to the enum."""
    u = User(
        user_id=_USER_ULID,
        auth0_sub="auth0|abc",
        tenant_id=_ULID,
        email="x@y.com",
        role="auditor",  # type: ignore[arg-type]
    )
    assert u.role is Role.AUDITOR


# ---------------------------- SQLAlchemy ↔ pydantic round-trip ----------


def test_tenant_row_to_pydantic_round_trip() -> None:
    now = datetime.now(UTC)
    row = TenantRow(
        tenant_id=_ULID,
        name="Acme",
        auth0_org_id="org_abc",
        created_at=now,
        suspended_at=None,
    )
    t = row.to_pydantic()
    assert isinstance(t, Tenant)
    assert t.tenant_id == _ULID
    assert t.auth0_org_id == "org_abc"
    assert t.name == "Acme"


def test_user_row_to_pydantic_round_trip() -> None:
    row = UserRow(
        user_id=_USER_ULID,
        auth0_sub="auth0|abc",
        tenant_id=_ULID,
        email="alice@example.com",
        role=Role.ADMIN.value,
        last_login_at=None,
    )
    u = row.to_pydantic()
    assert isinstance(u, User)
    assert u.role is Role.ADMIN
    assert u.email == "alice@example.com"


def test_user_row_role_field_accepts_string() -> None:
    """The DB stores the string; to_pydantic() lifts it to the enum."""
    row = UserRow(
        user_id=_USER_ULID,
        auth0_sub="auth0|abc",
        tenant_id=_ULID,
        email="bob@example.com",
        role="auditor",
        last_login_at=None,
    )
    assert row.to_pydantic().role is Role.AUDITOR


# ---------------------------- table metadata ---------------------------


def test_tenants_table_columns() -> None:
    from control_plane.tenants.models import Base

    cols = {c.name for c in Base.metadata.tables["tenants"].columns}
    assert cols == {"tenant_id", "name", "auth0_org_id", "created_at", "suspended_at"}


def test_users_table_columns() -> None:
    from control_plane.tenants.models import Base

    cols = {c.name for c in Base.metadata.tables["users"].columns}
    assert cols == {"user_id", "auth0_sub", "tenant_id", "email", "role", "last_login_at"}


def test_users_table_has_fk_to_tenants() -> None:
    from control_plane.tenants.models import Base

    fks = list(Base.metadata.tables["users"].columns["tenant_id"].foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "tenants"
