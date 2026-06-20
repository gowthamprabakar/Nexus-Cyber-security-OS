"""Fleet Test Level 1 — multi-cloud-posture (D.15) wiring smoke.

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions, modeled on
the cloud-posture (F.3) reference harness — D.15 is the Azure+GCP analog of that posture-feed
scan (it re-uses F.3's ``CloudPostureFinding`` / ``build_finding``, so the wire + spine shape
are identical).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). It does NOT measure precision/recall
or assert "the agent found the right violation" — that is L2 (v2 directive §3).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.contract import ExecutionContract
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
from multi_cloud_posture import agent as agent_mod
from multi_cloud_posture.agent import run
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding

_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
# kg tool names + the four readers the agent registers (Q: permitted_tools is a hard boundary).
_PERMITTED = [
    "read_azure_findings",
    "read_azure_activity",
    "read_gcp_findings",
    "read_gcp_iam_findings",
    "kg_upsert_asset",
    "kg_upsert_finding",
]
_CATEGORIES = (NodeCategory.CLOUD_RESOURCE, NodeCategory.MISCONFIGURATION_FINDING)
_OCSF_CLASS = 2003  # Compliance Finding (F.3 re-export; multi_cloud_posture.schemas)


def _scc_finding() -> GcpSccFinding:
    return GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/finding-001",
        parent="organizations/123/sources/456",
        resource_name="//storage.googleapis.com/projects/proj-xyz/buckets/public-bucket",
        category="PUBLIC_BUCKET",
        state="ACTIVE",
        severity="HIGH",
        description="bucket has public access",
        project_id="proj-xyz",
        detected_at=_NOW,
    )


def _seed_tool_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed D.15's reader surface with a deterministic GCP SCC finding.

    Reuses the established unit-test fake pattern (the reader is monkeypatched at the agent
    module level, since ``run`` calls the imported name). One PUBLIC_BUCKET SCC finding → one
    OCSF 2003 finding with a ``CLOUD_RESOURCE`` resource + ``MISCONFIGURATION_FINDING``.
    """

    async def fake_read_gcp_findings(*, path: Path, **_: Any) -> tuple[GcpSccFinding, ...]:
        del path
        return (_scc_finding(),)

    monkeypatch.setattr(agent_mod, "read_gcp_findings", fake_read_gcp_findings)


def _contract(tmp_path: Path, **kwargs: Any) -> ExecutionContract:
    """Build the L1 wiring contract, fixing ``required_outputs`` to D.15's actual outputs.

    The shared ``wiring_contract`` hardcodes ``["findings.json", "summary.md"]`` (the
    cloud-posture / runtime-threat convention), but D.15 writes ``findings.json`` +
    ``report.md``. ``Charter.assert_complete`` validates against ``contract.required_outputs``,
    so the contract must name the files the agent actually produces (matches the agent's own
    unit-test contract).
    """
    contract = wiring_contract(tmp_path, target_agent="multi_cloud_posture", **kwargs)
    return contract.model_copy(update={"required_outputs": ["findings.json", "report.md"]})


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_multi_cloud_posture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · CLOUD_RESOURCE +
    MISCONFIGURATION_FINDING written · audit chain hash-verifies · tenant isolation."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        feed_a = ws_a / "scc.json"
        feed_a.parent.mkdir(parents=True, exist_ok=True)
        feed_a.write_text("placeholder")
        contract_a = _contract(ws_a, permitted_tools=_PERMITTED, customer_id="tenant_a")
        report_a = await run(contract=contract_a, gcp_findings_feed=feed_a, semantic_store=store)

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CLOUD_RESOURCE
        )
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.MISCONFIGURATION_FINDING
        )

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        feed_b = ws_b / "scc.json"
        feed_b.parent.mkdir(parents=True, exist_ok=True)
        feed_b.write_text("placeholder")
        contract_b = _contract(
            ws_b,
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(contract=contract_b, gcp_findings_feed=feed_b, semantic_store=store)
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_multi_cloud_posture_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        feed = tmp_path / "scc.json"
        feed.write_text("placeholder")
        contract = _contract(tmp_path, permitted_tools=_PERMITTED, customer_id="t_off")
        report = await run(contract=contract, gcp_findings_feed=feed, semantic_store=None)
        assert report.total >= 1  # detection still runs offline
        # The injected store (unused by the run) stays empty — inert/byte-identical offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
