"""Posture rollup is wired into scan_run: writes posture.json, populates result, never fatal."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_scan_run_writes_posture_json_and_result(session_factory, tmp_path):
    res = await scan_run(
        session_factory=session_factory,
        tenant="t",
        sources=ScanSources(),
        workspace_root=tmp_path / "ws",
    )
    assert res.posture is not None
    posture_file = tmp_path / "ws" / "aggregation" / "posture.json"
    assert posture_file.exists()
    data = json.loads(posture_file.read_text())
    assert data["tenant"] == "t" and "coverage" in data


@pytest.mark.asyncio
async def test_rollup_failure_is_non_fatal(session_factory, tmp_path, monkeypatch):
    # Force the rollup to blow up; the scan must still return.
    import meta_harness.posture as posture_mod

    async def _boom(self, **kwargs):
        raise RuntimeError("rollup exploded")

    monkeypatch.setattr(posture_mod.PostureRollup, "compute", _boom)
    res = await scan_run(
        session_factory=session_factory,
        tenant="t",
        sources=ScanSources(),
        workspace_root=tmp_path / "ws",
    )
    assert res.posture is None  # rollup failed...
    assert isinstance(res.feeders, list)  # ...but the scan still produced its authoritative output
