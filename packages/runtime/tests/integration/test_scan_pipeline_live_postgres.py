"""Gated (NEXUS_LIVE_POSTGRES=1): scan_run operating-path e2e against REAL Postgres.

Proves what the SQLite CI test in test_scan_pipeline_e2e.py cannot:
- DB-level persistence — nodes written by data-security and identity agents are
  durably stored in Postgres and readable from real SQLAlchemy sessions.
- The full operating path (scan_run -> correlate_all -> AttackPathRanker) produces
  a confirmed ranked attack path on a freshly-migrated Postgres database.

Skip by default (CI); enable with:

    docker compose -f docker/docker-compose.dev.yml up -d postgres
    NEXUS_LIVE_POSTGRES=1 uv run pytest \\
        packages/runtime/tests/integration/test_scan_pipeline_live_postgres.py -v
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
from charter.memory.provisioning import build_session_factory
from identity.tools.aws_iam import IamRole, IdentityListing
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres",
)

# ---------------------------------------------------------------------------
# DSN constants — distinct DB name so we don't clobber other live-postgres tests
# ---------------------------------------------------------------------------

_DEFAULT_ADMIN_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/postgres"
_DEFAULT_TARGET_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/nexus_scan_pipeline_test"

_TARGET_URL = os.environ.get("NEXUS_LIVE_POSTGRES_URL", _DEFAULT_TARGET_URL)
_ADMIN_URL = os.environ.get("NEXUS_LIVE_POSTGRES_ADMIN_URL", _DEFAULT_ADMIN_URL)

# ---------------------------------------------------------------------------
# Test constants — match the Task 3 scenario exactly
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_TENANT = "tenant-pg-e2e"
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN_ROLE_ARN = "arn:aws:iam::123456789012:role/AdminRole"
_BUCKET_NAME = "acme-pii"


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
# Helpers — duplicated from test_scan_pipeline_e2e.py (same scenario)
# ---------------------------------------------------------------------------


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _write_public_pii_inventory(base_dir: Path) -> tuple[Path, Path]:
    """Write a canonical public-PII bucket inventory that data-security will classify.

    Returns (inventory_path, objects_path).
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    inventory = {
        "buckets": [
            {
                "name": _BUCKET_NAME,
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
                "bucket": _BUCKET_NAME,
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


def _admin_identity_listing() -> IdentityListing:
    """One role with AdministratorAccess — identity will write HAS_ACCESS_TO every resource."""
    role = IamRole(
        arn=_ADMIN_ROLE_ARN,
        name="AdminRole",
        role_id="AROA-ADMINROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


# ---------------------------------------------------------------------------
# Gated test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_e2e_on_real_postgres(
    tmp_path: Path,
    postgres_dsn: str,
) -> None:
    """Full scan_run against a freshly-migrated Postgres DB.

    Asserts:
    1. All feeders complete without exception (ok=True).
    2. res.confirmed is non-empty — the operating path produces a ranked attack
       path on real Postgres (not just in-memory SQLite).
    """
    factory = await build_session_factory(postgres_dsn, migrate=True)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)
    listing = _admin_identity_listing()

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
    )

    res = await scan_run(
        session_factory=factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    # Both feeders must be present — guards against a silently-dropped feeder making
    # ``all(f.ok)`` vacuously true over a shorter list (mirrors the SQLite e2e).
    feeder_names = {f.agent for f in res.feeders}
    assert "data-security" in feeder_names, f"data-security feeder missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity feeder missing from {feeder_names}"

    assert res.confirmed, "operating path must produce a ranked path on real Postgres"

    # The public-PII fixture forms the IDENTITY->HAS_ACCESS_TO->CLOUD_RESOURCE->EXPOSES_DATA
    # chain (mirrors the SQLite e2e). confirmed is expected-loss-ordered now, not severity —
    # ordering is proven by test_crown_jewel_outranks_single_store_by_expected_loss.
    path_types = [p.path_type for p in res.confirmed]
    assert "fine_grained_data" in path_types, (
        f"fine_grained_data path must form on real Postgres; got {path_types}"
    )
