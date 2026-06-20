"""Fleet Test Level 1 — network-threat (D.4 Network IDS) wiring smoke.

Tier A: writes the network topology + emits OCSF 2004 findings → the full §2.3 wiring
assertions. Modeled on the runtime-threat reference harness (the event-push detection shape):
the feed readers are patched at the agent module's import level (the agent's own unit-test
pattern) and a feed file path is passed so INGEST runs. A single Suricata alert drives the
finding (``network_suricata`` discriminator); a single VPC flow drives the CLOUD_RESOURCE
endpoint nodes the kg_writer upserts.

L1 is SMOKE, not capability — it proves the plumbing only. Precision/recall is L2.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
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
from network_threat import agent as agent_mod
from network_threat.agent import run
from network_threat.schemas import FlowRecord, SuricataAlert, SuricataAlertSeverity

_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_PERMITTED = ["read_suricata_alerts", "read_vpc_flow_logs", "read_dns_logs"]
_CATEGORIES = (NodeCategory.CLOUD_RESOURCE,)
_OCSF_CLASS = 2004  # Detection Finding (network_threat.schemas)


def _suricata() -> SuricataAlert:
    return SuricataAlert(
        timestamp=_NOW,
        src_ip="203.0.113.5",
        dst_ip="10.0.1.42",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        signature_id=2001234,
        signature="ET MALWARE Suspicious TLS",
        severity=SuricataAlertSeverity.HIGH,
    )


def _flow() -> FlowRecord:
    return FlowRecord(
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        src_port=49152,
        dst_port=443,
        protocol=6,
        bytes_transferred=100,
        packets=1,
        start_time=_NOW,
        end_time=_NOW + timedelta(seconds=0.5),
        action="ACCEPT",
    )


def _patch_readers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    alerts: Sequence[SuricataAlert],
    flows: Sequence[FlowRecord],
) -> None:
    async def fake_suricata(*, path: Path, **_: Any) -> tuple[SuricataAlert, ...]:
        return tuple(alerts)

    async def fake_vpc(*, path: Path, **_: Any) -> tuple[FlowRecord, ...]:
        return tuple(flows)

    monkeypatch.setattr(agent_mod, "read_suricata_alerts", fake_suricata)
    monkeypatch.setattr(agent_mod, "read_vpc_flow_logs", fake_vpc)


def _nt_contract(tmp_path: Path, **kwargs: Any) -> Any:
    """``wiring_contract`` with D.4's actual output artifacts.

    The shared builder declares ``required_outputs=["findings.json", "summary.md"]`` (the
    fleet-wide convention runtime-threat etc. follow), but D.4's ``run()`` writes
    ``findings.json`` + ``report.md`` — so ``ctx.assert_complete()`` would fail on the missing
    ``summary.md``. Override ``required_outputs`` to the artifacts D.4 genuinely emits; every
    other field stays the shared builder's.
    """
    contract = wiring_contract(tmp_path, **kwargs)
    return contract.model_copy(update={"required_outputs": ["findings.json", "report.md"]})


def _write_feed(workspace: Path, name: str) -> Path:
    feed = workspace / name
    feed.parent.mkdir(parents=True, exist_ok=True)
    feed.write_text("placeholder")
    return feed


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_network_threat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid (+ network_suricata discriminator) ·
    CLOUD_RESOURCE written · audit chain hash-verifies · tenant isolation."""
    _patch_readers(monkeypatch, alerts=[_suricata()], flows=[_flow()])
    async with in_memory_semantic_store() as store:
        ws_a = tmp_path / "a"
        suricata_a = _write_feed(ws_a, "eve.json")
        vpc_a = _write_feed(ws_a, "flow.log")
        contract_a = _nt_contract(
            ws_a,
            target_agent="network_threat",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            cloud_api_calls=10,
        )
        report_a = await run(
            contract=contract_a,
            suricata_feed=suricata_a,
            vpc_flow_feed=vpc_a,
            semantic_store=store,
        )

        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)
        # Per-agent discriminator (the class-specific check the shared helper leaves to the harness)
        assert findings[0]["finding_info"]["types"][0] == "network_suricata"

        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CLOUD_RESOURCE
        )
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation
        ws_b = tmp_path / "b"
        suricata_b = _write_feed(ws_b, "eve.json")
        vpc_b = _write_feed(ws_b, "flow.log")
        contract_b = _nt_contract(
            ws_b,
            target_agent="network_threat",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            cloud_api_calls=10,
        )
        await run(
            contract=contract_b,
            suricata_feed=suricata_b,
            vpc_flow_feed=vpc_b,
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_network_threat_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _patch_readers(monkeypatch, alerts=[_suricata()], flows=[_flow()])
    async with in_memory_semantic_store() as store:
        suricata = _write_feed(tmp_path, "eve.json")
        vpc = _write_feed(tmp_path, "flow.log")
        contract = _nt_contract(
            tmp_path,
            target_agent="network_threat",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            cloud_api_calls=10,
        )
        report = await run(
            contract=contract,
            suricata_feed=suricata,
            vpc_flow_feed=vpc,
            semantic_store=None,
        )
        assert report.total >= 1
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
