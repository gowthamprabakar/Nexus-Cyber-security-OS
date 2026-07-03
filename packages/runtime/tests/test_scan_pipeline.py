"""scan_run runs the feeders whose sources are present, records per-feeder outcomes,
and always calls analyze on the shared store.

NOTE: build_session_factory (charter.memory.provisioning) is for Postgres only (runs
Alembic migrations). For in-memory SQLite we follow the established test pattern in
test_correlation_run.py: create_async_engine + Base.metadata.create_all + async_sessionmaker.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from charter.memory.models import Base
from nexus_runtime.scan_pipeline import FeederOutcome, ScanRunResult, ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_TENANT = "tenant-scan-pipeline"


# ---------------------------------------------------------------------------
# Session factory fixture — same pattern as test_correlation_run.py
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


@pytest.mark.asyncio
async def test_scan_run_records_feeder_outcomes_and_analyzes(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """data-security feeder fires, records ok=True, and analyze always runs.

    Inventory JSON uses the canonical ``{"buckets": [...]}`` top-level shape.
    Objects JSON uses the canonical ``{"objects": [...]}`` shape with
    ``content_sample_b64`` as the wire field (decoded by ObjectSample._decode_b64).
    One public bucket + one PII object ensures the feeder does real work.
    """
    # Canonical inventory shape: {"buckets": [...]}
    inv = tmp_path / "inv.json"
    inv.write_text(
        json.dumps(
            {
                "buckets": [
                    {
                        "name": "acme-pii",
                        "region": "us-east-1",
                        "account_id": "111122223333",
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
        ),
        encoding="utf-8",
    )

    # Canonical objects shape: {"objects": [...]} with content_sample_b64
    objs = tmp_path / "objs.json"
    objs.write_text(
        json.dumps(
            {
                "objects": [
                    {
                        "bucket": "acme-pii",
                        "key": "data.csv",
                        "content_sample_b64": _b64(b"name,ssn\nalice,123-45-6789"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sources = ScanSources(ds_inventory_feed=inv, ds_objects_feed=objs)
    result = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    assert isinstance(result, ScanRunResult)
    ds = next(f for f in result.feeders if f.agent == "data-security")
    assert ds == FeederOutcome(agent="data-security", ok=True, error=None)
    # analyze ran (confirmed/candidates are lists, possibly empty on this minimal graph)
    assert isinstance(result.confirmed, list) and isinstance(result.candidates, list)
