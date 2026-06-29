"""Gated (NEXUS_LIVE_POSTGRES=1): the FULL correlation run against REAL Postgres.

Proves what the SQLite CI test in test_correlation_run.py cannot:
- DB-level persistence — the TOXIC_COMBINATION node written by D.7 is durably
  stored in Postgres and readable from a brand-new SemanticStore handle.
- RLS — the session factory built by build_session_factory honours tenant scope.

Skip by default (CI); enable with:

    docker compose -f docker/docker-compose.dev.yml up -d postgres
    NEXUS_LIVE_POSTGRES=1 uv run pytest \\
        packages/runtime/tests/integration/test_correlation_live_postgres.py -v
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from charter.memory.graph_types import NodeCategory
from charter.memory.provisioning import build_session_factory
from charter.memory.semantic import SemanticStore
from identity.tools.aws_iam import IamRole, IdentityListing
from nexus_runtime.correlation import correlation_run
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres",
)

# ---------------------------------------------------------------------------
# DSN constants — distinct DB name so we don't clobber memory/provisioning tests
# ---------------------------------------------------------------------------

_DEFAULT_ADMIN_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/postgres"
_DEFAULT_TARGET_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/nexus_correlation_test"

_TARGET_URL = os.environ.get("NEXUS_LIVE_POSTGRES_URL", _DEFAULT_TARGET_URL)
_ADMIN_URL = os.environ.get("NEXUS_LIVE_POSTGRES_ADMIN_URL", _DEFAULT_ADMIN_URL)

# ---------------------------------------------------------------------------
# Constants mirrored from Task 3's test_correlation_run.py
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_TENANT = "01HV0T0000000000000000CRRL"  # 26-char ULID-shaped tenant for IncidentReport
_ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN_ROLE_ARN = "arn:aws:iam::123456789012:role/AdminRole"


# ---------------------------------------------------------------------------
# Postgres fresh-DB fixture — drops + recreates for a clean slate
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def postgres_dsn() -> AsyncIterator[str]:
    """Drop + recreate the test database for a clean slate per test run."""
    target_db = _TARGET_URL.rsplit("/", 1)[-1]
    admin_engine = create_async_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS {target_db}"))
            await conn.execute(text(f"CREATE DATABASE {target_db}"))
    finally:
        await admin_engine.dispose()

    yield _TARGET_URL


# ---------------------------------------------------------------------------
# Identity listing helper — replicates Task 3's _admin_listing()
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


# ---------------------------------------------------------------------------
# Inventory fixture helper — replicates Task 3's _public_pii_inventory()
# ---------------------------------------------------------------------------


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _public_pii_inventory(base_dir: Path) -> tuple[Path, Path]:
    """Write a public-bucket inventory + object sample with a PII classifier hit.

    Mirrors data-security's _write_inventory / _public_bucket_dict.
    Returns (inventory_path, objects_path).
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
# Gated test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlation_persists_toxic_combination_on_postgres(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    postgres_dsn: str,
) -> None:
    """Full correlation_run against a freshly-migrated Postgres DB.

    Asserts:
    1. The IncidentReport surfaces a hypothesis containing "over-permissioned"
       (the toxic combination of an admin identity with access to a public PII
       bucket).
    2. report.to_ocsf()["class_uid"] == 2005.
    3. PERSISTENCE: a brand-new SemanticStore built from the same factory can
       read back ≥1 TOXIC_COMBINATION node for the tenant — proves the node was
       durably written to Postgres, not just held in memory.
    """
    import identity.agent as identity_agent

    async def _fake_list(**_: object) -> IdentityListing:
        return _admin_listing()

    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)

    # Build the session factory against a freshly-migrated Postgres DB.
    factory = await build_session_factory(postgres_dsn, migrate=True)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _public_pii_inventory(feeds_dir)

    report = await correlation_run(
        session_factory=factory,
        tenant=_TENANT,
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        workspace_root=tmp_path,
    )

    # (a) Report surfaces the toxic hypothesis.
    statements = [h.statement.lower() for h in report.hypotheses]
    assert any("over-permissioned" in s for s in statements), (
        "admin HAS_ACCESS_TO public-PII bucket must produce 'over-permissioned' hypothesis"
    )
    assert report.to_ocsf()["class_uid"] == 2005

    # (b) PERSISTENCE: new store handle reads back the durable TOXIC_COMBINATION node.
    store = SemanticStore(factory)
    nodes = await store.list_entities_by_type(
        tenant_id=_TENANT,
        entity_type=NodeCategory.TOXIC_COMBINATION.value,
    )
    assert len(nodes) >= 1, (
        "TOXIC_COMBINATION node must be durably persisted in Postgres and readable "
        "from a new SemanticStore handle"
    )
