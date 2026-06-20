"""Fleet Test Level 1 — synthesis (D.13) wiring smoke.

Tier A (LLM-driven): synthesis reads sibling-agent workspaces (D.7 / D.6 / F.3 findings.json),
runs a 3-stage LLM narration (1 outline + N section + 1 exec-summary calls), and emits **one
bare** OCSF 2004 finding to ``synthesis_finding.json`` (the file is a single bare OCSF dict — no
``{"findings": ...}`` wrapper and no ``nexus_envelope``; ``assert_ocsf_valid`` handles bare
findings). It persists a raw ``entity_type="synthesis_report"`` node to the graph.

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). Capability (precision/recall) is L2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)
from synthesis.agent import DEFAULT_MODEL_PIN, run

_PERMITTED = ["read_sibling_workspaces"]
# synthesis is a pre-ADR-018 raw-entity-type writer (flagged for a v0.5 NodeCategory migration).
_CATEGORIES = ("synthesis_report",)
_OCSF_CLASS = 2004  # Detection Finding (synthesis.ocsf.schema)
_REQUIRED_OUTPUTS = ["narrative.md", "executive_summary.md", "synthesis_finding.json"]
_COMPLETION = "narrative.md AND executive_summary.md exist"


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=100, output_tokens=50),
        model_pin=DEFAULT_MODEL_PIN,
    )


def _outline_json(sections: int = 2) -> str:
    section_list = [
        {
            "heading": f"Section {i + 1}",
            "intent": f"Intent {i + 1}",
            "cited_finding_ids": [f"CSPM-AWS-{i + 1:03d}"],
        }
        for i in range(sections)
    ]
    return json.dumps({"overall_narrative_intent": "Cover the findings.", "sections": section_list})


def _exec_summary_json() -> str:
    return json.dumps(
        {
            "paragraph": (
                "The scan window surfaced findings of mixed severity. Compliance posture is "
                "degraded; review the per-section narrative."
            ),
            "key_metrics": {"total_findings": 2, "critical": 0, "high": 1},
        }
    )


def _clean_responses(sections: int = 2) -> list[LLMResponse]:
    """1 outline + N section bodies + 1 exec-summary = the synthesis 3-stage LLM call sequence."""
    out = [_resp(_outline_json(sections))]
    out.extend(_resp(f"Body of section {i + 1} - operator-grade prose.") for i in range(sections))
    out.append(_resp(_exec_summary_json()))
    return out


def _stub_finding(uid: str, *, severity_id: int = 4) -> dict[str, Any]:
    return {
        "class_uid": 2003,
        "severity_id": severity_id,
        "finding_info": {"uid": uid, "title": f"Finding {uid}"},
    }


def _seed_sibling_workspace(workspace: Path, findings: list[dict[str, Any]]) -> Path:
    """Seed a sibling-agent workspace with the findings.json the reader consumes."""
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "findings.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return workspace


def _finding(workspace: Path) -> dict[str, Any]:
    # synthesis_finding.json is a single bare OCSF 2004 dict (no list, no wrapper).
    payload = json.loads((workspace / "synthesis_finding.json").read_text())
    assert isinstance(payload, dict), "synthesis_finding.json must be a single bare OCSF dict"
    return payload


@pytest.mark.asyncio
async def test_wiring_synthesis(tmp_path: Path) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid · synthesis_report entity written ·
    audit chain hash-verifies · tenant isolation."""
    async with in_memory_semantic_store() as store:
        # tenant A
        cp_ws_a = _seed_sibling_workspace(
            tmp_path / "a" / "cspm",
            [_stub_finding("CSPM-AWS-001"), _stub_finding("CSPM-AWS-002")],
        )
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a,
            target_agent="synthesis",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        report_a = await run(
            contract=contract_a,
            llm_provider=FakeLLMProvider(_clean_responses(sections=2)),
            cloud_posture_workspace=cp_ws_a,
            semantic_store=store,
        )

        # run-completes + produced a finding (synthesis always emits one OCSF 2004 finding)
        assert report_a.total_sections >= 1
        finding = _finding(ws_a / "ws")

        # OCSF valid
        assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the raw "synthesis_report" entity type
        await assert_entity_written(store, tenant_id="tenant_a", category="synthesis_report")

        # audit chain hash-verifies (Charter writes audit.jsonl in the workspace)
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: seed + run under tenant_b → disjoint subgraph
        cp_ws_b = _seed_sibling_workspace(tmp_path / "b" / "cspm", [_stub_finding("CSPM-AWS-010")])
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="synthesis",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        await run(
            contract=contract_b,
            llm_provider=FakeLLMProvider(_clean_responses(sections=1)),
            cloud_posture_workspace=cp_ws_b,
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_synthesis_inert_offline(tmp_path: Path) -> None:
    """No semantic_store → no graph writes; the OCSF finding still emits (byte-identical offline:
    synthesis emission is sibling-workspace-driven, not graph-gated)."""
    async with in_memory_semantic_store() as store:
        cp_ws = _seed_sibling_workspace(tmp_path / "cspm", [_stub_finding("CSPM-AWS-001")])
        contract = wiring_contract(
            tmp_path,
            target_agent="synthesis",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        report = await run(
            contract=contract,
            llm_provider=FakeLLMProvider(_clean_responses(sections=1)),
            cloud_posture_workspace=cp_ws,
            semantic_store=None,
        )
        assert report.total_sections >= 1
        finding = _finding(tmp_path / "ws")
        assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)
        # The injected store (unused by the run) stays empty — inert offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
