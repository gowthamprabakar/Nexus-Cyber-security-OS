"""Fleet Test Level 1 — runtime-threat (D.3) wiring smoke (reference harness).

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions. The second of
the two L1 reference harnesses (with cloud-posture); together they lock the pattern across the
two dominant Tier-A shapes (posture-feed scan vs. event-push detection).

L1 is SMOKE, not capability — proves plumbing only. Capability (precision/recall/FP) is L2.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.memory.graph_types import NodeCategory
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)
from runtime_threat import agent as agent_mod
from runtime_threat.agent import run
from runtime_threat.tools.falco import FalcoAlert

_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_PERMITTED = ["falco_alerts_read", "tracee_alerts_read", "osquery_run"]
_CATEGORIES = (NodeCategory.PROCESS_EVENT,)
_OCSF_CLASS = 2004  # Detection Finding (runtime_threat.schemas)


def _falco_alert() -> FalcoAlert:
    return FalcoAlert(
        time=_NOW,
        rule="Terminal shell in container",
        priority="Critical",
        output="shell spawned",
        output_fields={"container.id": "abc123def456", "k8s.pod.name": "frontend"},
        tags=("container", "shell", "process"),
    )


def _patch_falco(monkeypatch: pytest.MonkeyPatch, alerts: Sequence[FalcoAlert]) -> None:
    async def fake(**_: Any) -> tuple[FalcoAlert, ...]:
        return tuple(alerts)

    monkeypatch.setattr(agent_mod, "falco_alerts_read", fake)


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_runtime_threat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid (+ runtime_process discriminator) ·
    PROCESS_EVENT written · audit chain hash-verifies · tenant isolation."""
    _patch_falco(monkeypatch, [_falco_alert()])
    async with in_memory_semantic_store() as store:
        ws_a = tmp_path / "a"
        feed_a = ws_a / "falco.jsonl"
        feed_a.parent.mkdir(parents=True, exist_ok=True)
        feed_a.write_text("placeholder")
        contract_a = wiring_contract(
            ws_a,
            target_agent="runtime_threat",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            cloud_api_calls=10,
        )
        report_a = await run(contract=contract_a, falco_feed=feed_a, semantic_store=store)

        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)
        # Per-agent discriminator (the class-specific check the shared helper leaves to the harness)
        assert findings[0]["finding_info"]["types"][0] == "runtime_process"

        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.PROCESS_EVENT
        )
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation
        ws_b = tmp_path / "b"
        feed_b = ws_b / "falco.jsonl"
        feed_b.parent.mkdir(parents=True, exist_ok=True)
        feed_b.write_text("placeholder")
        contract_b = wiring_contract(
            ws_b,
            target_agent="runtime_threat",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            cloud_api_calls=10,
        )
        await run(contract=contract_b, falco_feed=feed_b, semantic_store=store)
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_runtime_threat_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _patch_falco(monkeypatch, [_falco_alert()])
    async with in_memory_semantic_store() as store:
        feed = tmp_path / "falco.jsonl"
        feed.write_text("placeholder")
        contract = wiring_contract(
            tmp_path,
            target_agent="runtime_threat",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            cloud_api_calls=10,
        )
        report = await run(contract=contract, falco_feed=feed, semantic_store=None)
        assert report.total >= 1
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
