"""Fleet Test Level 1 — aispm (D.11 AI Posture) wiring smoke.

Tier A: writes the AI spine + emits OCSF 2003 findings → the full §2.3 wiring assertions.
Modeled on the cloud-posture reference harness. AISPM's finding-bearing path drives the AWS
AI-discovery connector through a deterministic injected reader (the same fake the agent's own
unit suite uses) — Garak prompt-injection stays OFF (default), so the emitted class is the 2003
posture class, not the 2004 detection class.

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes the AI
spine, OCSF valid, tenant isolated, audit chain clean, inert offline). Precision/recall is L2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from aispm.agent import run
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

_PERMITTED = ["discover_aws_ai", "discover_azure_ai", "discover_gcp_ai", "probe_garak"]
_CATEGORIES = (NodeCategory.CLOUD_RESOURCE, NodeCategory.AI_SERVICE, NodeCategory.AI_MODEL)
_OCSF_CLASS = 2003  # Compliance Finding (aispm.schemas; the no-Garak posture class)


class _FakeAwsAiReader:
    """Deterministic AWS-AI reader fake — one SageMaker endpoint with inference logging OFF,
    which yields a single OCSF 2003 posture finding + the AI-spine nodes."""

    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        return [{"name": "prod", "data_capture_enabled": False, "model_name": "m1"}]

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        return []

    def bedrock_logging_enabled(self) -> bool | None:
        return True

    def bedrock_guardrail_count(self) -> int:
        return 1


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_aispm(tmp_path: Path) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · CLOUD_RESOURCE + AI_SERVICE +
    AI_MODEL written · audit chain hash-verifies · tenant isolation."""
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a, target_agent="aispm", permitted_tools=_PERMITTED, customer_id="tenant_a"
        )
        report_a = await run(
            contract=contract_a,
            aws_account_id="111122223333",
            aws_reader=_FakeAwsAiReader(),
            semantic_store=store,
        )

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding) — no-Garak run is the 2003 posture class
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected AI spine node types
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CLOUD_RESOURCE
        )
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.AI_SERVICE)
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.AI_MODEL)

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="aispm",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(
            contract=contract_b,
            aws_account_id="111122223333",
            aws_reader=_FakeAwsAiReader(),
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_aispm_inert_offline(tmp_path: Path) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path,
            target_agent="aispm",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
        )
        report = await run(
            contract=contract,
            aws_account_id="111122223333",
            aws_reader=_FakeAwsAiReader(),
            semantic_store=None,
        )
        assert report.total >= 1  # detection still runs offline
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
