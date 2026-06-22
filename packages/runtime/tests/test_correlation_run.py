"""CI orchestration e2e (in-memory store, fixture cloud data). The HAS_ACCESS_TO edge
is DERIVED by real identity code from a fixture admin IdentityListing — not supplied.
NOTE: SQLite does not enforce RLS; DB-level tenant isolation is proven by the gated
Postgres test, not here."""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from charter.memory import SemanticStore
from charter.memory.graph_types import NodeCategory
from charter.memory.models import Base
from identity.tools.aws_iam import IamRole, IdentityListing
from nexus_runtime.correlation import correlation_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_TENANT = "01HV0T0000000000000000CRRL"  # 26-char ULID-shaped tenant for IncidentReport
_ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN_ROLE_ARN = "arn:aws:iam::123456789012:role/AdminRole"
_READ_ONLY_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_READ_ONLY_ROLE_ARN = "arn:aws:iam::123456789012:role/ReadOnlyRole"


# ---------------------------------------------------------------------------
# Session factory fixture — mirrors investigation's test pattern exactly
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Identity listing fixtures — mirror identity test helpers
# ---------------------------------------------------------------------------


def _admin_listing() -> IdentityListing:
    """One role carrying AdministratorAccess — identity will write HAS_ACCESS_TO."""
    role = IamRole(
        arn=_ADMIN_ROLE_ARN,
        name="AdminRole",
        role_id="AROA-ADMINROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


def _non_admin_listing() -> IdentityListing:
    """One role with ReadOnly — no admin grant, no HAS_ACCESS_TO written."""
    role = IamRole(
        arn=_READ_ONLY_ROLE_ARN,
        name="ReadOnlyRole",
        role_id="AROA-READONLYROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_READ_ONLY_POLICY,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


# ---------------------------------------------------------------------------
# Inventory fixture — mirrors data-security test helpers
# ---------------------------------------------------------------------------


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _public_pii_inventory(base_dir: Path) -> tuple[Path, Path]:
    """Write a public bucket inventory + object sample with a PII classifier hit.

    Mirrors data-security's _write_inventory / _public_bucket_dict.
    One public bucket 'acme-pii' — data-security writes is_public=True
    + EXPOSES_DATA edge to the DATA_CLASSIFICATION node.

    Returns (inventory_path, objects_path) — the caller must pass both to
    correlation_run so the data-security classifier fires and writes EXPOSES_DATA.
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    inventory = {
        "buckets": [
            {
                "name": "acme-pii",
                "region": "us-east-1",
                "account_id": "123456789012",
                "acl": {
                    "grants_all_users": ["READ"],
                    "grants_authenticated_users": [],
                },
                "public_access_block": {
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "encryption": {"algorithm": "AES256", "kms_master_key_id": None},
                "policy_json": None,
                "tags": {},
            }
        ]
    }
    objects = {
        "objects": [
            {
                "bucket": "acme-pii",
                "key": "data.csv",
                "content_sample_b64": _b64(b"name,ssn\nalice,123-45-6789"),
            }
        ]
    }
    inv_path = base_dir / "inv.json"
    obj_path = base_dir / "objects.json"
    inv_path.write_text(json.dumps(inventory), encoding="utf-8")
    obj_path.write_text(json.dumps(objects), encoding="utf-8")
    return inv_path, obj_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlation_run_surfaces_persisted_toxic_combination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Positive path: admin role → all resources → public PII bucket → toxic combo surfaces.

    identity's aws_iam_list_identities is monkeypatched to return an admin role.
    data-security receives a public PII bucket via fixture feed.
    D.7 reads the combined graph and surfaces 'over-permissioned' in a hypothesis.
    """
    import identity.agent as identity_agent

    async def _fake_list(**_: object) -> IdentityListing:
        return _admin_listing()

    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _public_pii_inventory(feeds_dir)
    report = await correlation_run(
        session_factory=session_factory,
        tenant=_TENANT,
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        workspace_root=tmp_path,
    )

    statements = [h.statement.lower() for h in report.hypotheses]
    assert any("over-permissioned" in s for s in statements), (
        "real toxic combo must surface: admin HAS_ACCESS_TO public-PII bucket"
    )
    assert report.to_ocsf()["class_uid"] == 2005

    # C-1: prove the TOXIC_COMBINATION node was actually persisted (not just returned).
    store = SemanticStore(session_factory)
    toxic_nodes = await store.list_entities_by_type(
        tenant_id=_TENANT,
        entity_type=NodeCategory.TOXIC_COMBINATION.value,
    )
    assert len(toxic_nodes) >= 1, "TOXIC_COMBINATION node must be written to the store"


@pytest.mark.asyncio
async def test_correlation_run_dark_when_no_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Negative path: non-admin role → no HAS_ACCESS_TO written → no toxic combo.

    When identity writes no admin-grade grants, the graph has CLOUD_RESOURCE +
    EXPOSES_DATA but no IDENTITY → HAS_ACCESS_TO edge, so D.7 stays dark.
    """
    import identity.agent as identity_agent

    async def _fake_list(**_: object) -> IdentityListing:
        return _non_admin_listing()

    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _public_pii_inventory(feeds_dir)
    report = await correlation_run(
        session_factory=session_factory,
        tenant=_TENANT,
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        workspace_root=tmp_path,
    )

    statements = [h.statement.lower() for h in report.hypotheses]
    assert not any("over-permissioned" in s for s in statements), (
        "non-admin role must not produce toxic combination hypothesis"
    )
    assert report.to_ocsf()["class_uid"] == 2005
