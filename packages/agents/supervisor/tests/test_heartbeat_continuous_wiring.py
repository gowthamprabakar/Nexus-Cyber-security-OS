"""Phase C SS1 — Heartbeat wires the continuous source into its trigger set."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from supervisor import heartbeat as hb_mod
from supervisor.heartbeat import Heartbeat
from supervisor.schemas import IncomingTask, TriggerSource


def _continuous_task() -> IncomingTask:
    return IncomingTask(
        task_id="cont-1",
        customer_id="cust-A",
        trigger_source=TriggerSource.CONTINUOUS,
        target_agent="compliance",
        description="continuous scheduler due: compliance",
        received_at=datetime(2026, 6, 13, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_continuous_triggers_reach_agent_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    async def fake_agent_run(**kwargs: Any) -> Any:
        captured["triggers"] = kwargs["triggers"]
        return None

    monkeypatch.setattr(hb_mod, "agent_run", fake_agent_run)

    async def continuous_source(customer_id: str) -> list[IncomingTask]:
        return [_continuous_task()]

    hb = Heartbeat(
        customer_id="cust-A",
        workspace_root=tmp_path,
        routing_rules=(),
        continuous_source=continuous_source,
        max_ticks=1,
    )
    await hb.tick_once()
    triggers = captured["triggers"]
    assert any(
        t.trigger_source is TriggerSource.CONTINUOUS and t.target_agent == "compliance"
        for t in triggers
    )


@pytest.mark.asyncio
async def test_default_no_continuous_source_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    async def fake_agent_run(**kwargs: Any) -> Any:
        captured["triggers"] = kwargs["triggers"]
        return None

    monkeypatch.setattr(hb_mod, "agent_run", fake_agent_run)
    hb = Heartbeat(customer_id="cust-A", workspace_root=tmp_path, routing_rules=(), max_ticks=1)
    await hb.tick_once()
    # no continuous source -> no continuous triggers (default behaviour preserved).
    assert all(t.trigger_source is not TriggerSource.CONTINUOUS for t in captured["triggers"])
