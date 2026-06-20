"""Fleet Test Level 1 — curiosity (D.12) wiring smoke.

Tier A (LLM-driven, generative): curiosity reads aggregate sibling state, detects region
coverage-gaps, and runs a single LLM call to hypothesize. It emits **bare** OCSF 2004 findings
to ``curiosity_findings.json`` (the file is a bare JSON **list** of OCSF events — no
``{"findings": ...}`` wrapper and no ``nexus_envelope``; ``assert_ocsf_valid`` handles bare
findings) and persists raw ``entity_type="hypothesis"`` nodes to the graph.

curiosity only produces hypotheses when the seeded SemanticStore has a region-gap: an
``aws_account_region`` entity with assets but NO recent finding aggregates. We drive that with a
``FakeLLMProvider`` whose response cites the seeded region (the WI-X11 hallucination guard
hard-blocks a hypothesis citing an undetected gap, so the cited region must match).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). Capability (precision/recall) is L2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from charter.memory.semantic import SemanticStore
from curiosity.agent import DEFAULT_MODEL_PIN, run
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)

_PERMITTED = ["read_sibling_state"]
# curiosity is a pre-ADR-018 raw-entity-type writer (flagged for a v0.5 NodeCategory migration).
_CATEGORIES = ("hypothesis",)
_OCSF_CLASS = 2004  # Detection Finding (curiosity.ocsf.schema)
_REGION = "us-east-1"
_REQUIRED_OUTPUTS = ["hypotheses.md", "probe_directives.json", "curiosity_findings.json"]
_COMPLETION = "hypotheses.md AND probe_directives.json exist"


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=100, output_tokens=50),
        model_pin=DEFAULT_MODEL_PIN,
    )


def _hypothesis_json(region: str = _REGION) -> str:
    """One valid hypothesis citing ``region`` (must match the seeded gap — WI-X11 guard)."""
    return json.dumps(
        {
            "hypotheses": [
                {
                    "statement": f"Region {region} appears under-scanned.",
                    "rationale": (
                        f"Region {region} has assets but no findings in 60 days. This is "
                        "consistent with either clean posture or a coverage gap. Recommend "
                        "running D.5 across the region's S3 buckets to establish a baseline."
                    ),
                    "probe_directive": {
                        "target_agent": "data_security",
                        "target_resource_arn": f"arn:aws:s3:::{region}-bucket-0",
                        "action": "scan",
                        "rationale_ref": "",
                    },
                    "cited_gap": {
                        "region": region,
                        "asset_count": 42,
                        "days_since_last_finding": 60,
                        "severity_hint": "medium",
                    },
                }
            ]
        }
    )


async def _seed_region_gap(store: SemanticStore, *, tenant_id: str, region: str = _REGION) -> None:
    """Seed a region with assets and NO finding aggregates → a coverage gap fires (asset_count
    >= 10 and days_since_last_finding sentinel -1 'no findings ever')."""
    await store.upsert_entity(
        tenant_id=tenant_id,
        entity_type="aws_account_region",
        external_id=region,
        properties={"asset_count": 42},
    )


def _findings(workspace: Path) -> list[dict[str, Any]]:
    # curiosity_findings.json is a bare JSON list of OCSF 2004 events (no wrapper).
    payload = json.loads((workspace / "curiosity_findings.json").read_text())
    assert isinstance(payload, list), "curiosity_findings.json must be a bare OCSF list"
    return payload


@pytest.mark.asyncio
async def test_wiring_curiosity(tmp_path: Path) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid · hypothesis entity written ·
    audit chain hash-verifies · tenant isolation."""
    async with in_memory_semantic_store() as store:
        # tenant A
        await _seed_region_gap(store, tenant_id="tenant_a")
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a,
            target_agent="curiosity",
            permitted_tools=_PERMITTED,
            customer_id="tenant_a",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        report_a = await run(
            contract=contract_a,
            llm_provider=FakeLLMProvider([_resp(_hypothesis_json())]),
            semantic_store=store,
        )

        # run-completes + produced findings
        assert report_a.total_claims >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the raw "hypothesis" entity type
        await assert_entity_written(store, tenant_id="tenant_a", category="hypothesis")

        # audit chain hash-verifies (Charter writes audit.jsonl in the workspace)
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: seed + run under tenant_b → disjoint subgraph
        await _seed_region_gap(store, tenant_id="tenant_b")
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="curiosity",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        await run(
            contract=contract_b,
            llm_provider=FakeLLMProvider([_resp(_hypothesis_json())]),
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_curiosity_inert_offline(tmp_path: Path) -> None:
    """No semantic_store → INGEST is empty → no gaps. The agent still completes and writes a
    (legitimately empty) curiosity_findings.json, and the injected store stays empty.

    Note: with semantic_store=None there is no detected gap, so the LLM short-circuits and the
    bare OCSF list is empty — the offline lane proves the no-graph-write invariant, not finding
    emission (which is gated on the graph-derived gap signal). assert_no_entities is the load-
    bearing offline assertion here.
    """
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path,
            target_agent="curiosity",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
            required_outputs=_REQUIRED_OUTPUTS,
            completion_condition=_COMPLETION,
        )
        report = await run(
            contract=contract,
            llm_provider=FakeLLMProvider([]),  # would raise if the LLM were called
            semantic_store=None,
        )
        assert report.total_claims == 0  # no store → no gap → no hypotheses
        # curiosity_findings.json still written (empty bare list) — artifact byte-shape preserved.
        assert _findings(tmp_path / "ws") == []
        # The injected store (unused by the offline run) stays empty — inert offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
