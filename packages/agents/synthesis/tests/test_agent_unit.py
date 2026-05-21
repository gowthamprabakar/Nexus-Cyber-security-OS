"""Unit tests — D.13 Synthesis agent driver (Task 9).

Tests build a minimal ``ExecutionContract`` against a tmp_path
workspace + use ``charter.llm.FakeLLMProvider`` to drive the LLM
calls. No live LLM; no live SemanticStore.

Coverage:
1. Happy path — 3 workspaces + clean LLM responses + no semantic_store.
2. Happy path with semantic_store — kg upsert called.
3. Q6 retry succeeds on second pass — review_retries=1, draft is clean.
4. Q6 retry budget exhausted — accepts degraded draft, review_retries=1.
5. OutlineCallError -> fallback narrative emitted.
6. ExecutiveSummaryCallError -> fallback.
7. Markdown files written to workspace.
8. SynthesisReport carries dedupe'd cited_finding_ids.
9. SynthesisReport.run_id, customer_id propagate from contract.
10. Narrator failure during Q6 retry -> fallback.
11. Missing workspaces tolerated (all None still runs).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from charter.memory.semantic import SemanticStore
from synthesis.agent import run
from synthesis.schemas import SynthesisReport


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="synthesis",
        customer_id="acme",
        task="Synthesis run",
        required_outputs=["narrative.md", "executive_summary.md"],
        budget=BudgetSpec(
            llm_calls=20,
            tokens=50_000,
            wall_clock_sec=120.0,
            cloud_api_calls=1,
            mb_written=10,
        ),
        permitted_tools=["read_sibling_workspaces"],
        completion_condition="narrative.md AND executive_summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _resp(text: str, *, input_tokens: int = 100, output_tokens: int = 50) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        model_pin="claude-haiku-4-5-20251001",
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


def _exec_summary_json(total: int = 1) -> str:
    return json.dumps(
        {
            "paragraph": (
                "The scan window surfaced findings of mixed severity. "
                "Compliance posture is degraded; review the per-section narrative."
            ),
            "key_metrics": {
                "total_findings": total,
                "critical": 0,
                "high": 1,
                "top_failing_control": "1.10",
            },
        }
    )


def _clean_responses(outline_sections: int = 2) -> list[LLMResponse]:
    out = [_resp(_outline_json(outline_sections))]
    for i in range(outline_sections):
        out.append(_resp(f"Body of section {i + 1} - operator-grade prose."))
    out.append(_resp(_exec_summary_json()))
    return out


def _write_workspace_findings(workspace: Path, findings: list[dict[str, Any]]) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "findings.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return workspace


def _stub_finding(uid: str, *, severity_id: int = 4) -> dict[str, Any]:
    return {
        "class_uid": 2003,
        "severity_id": severity_id,
        "finding_info": {"uid": uid, "title": f"Finding {uid}"},
    }


def _make_semantic_store() -> SemanticStore:
    entity_ids: dict[tuple[str, str], str] = {}

    async def fake_upsert_entity(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id, properties
        key = (entity_type, external_id)
        if key not in entity_ids:
            entity_ids[key] = f"ent_{entity_type}_{len(entity_ids)}"
        return entity_ids[key]

    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.side_effect = fake_upsert_entity
    return cast(SemanticStore, store)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_runs_end_to_end(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    cp_ws = _write_workspace_findings(
        tmp_path / "cspm",
        [_stub_finding("CSPM-AWS-001"), _stub_finding("CSPM-AWS-002")],
    )
    provider = FakeLLMProvider(_clean_responses(outline_sections=2))

    report = await run(
        contract,
        llm_provider=provider,
        cloud_posture_workspace=cp_ws,
    )

    assert isinstance(report, SynthesisReport)
    assert report.customer_id == "acme"
    assert report.run_id == contract.delegation_id
    assert report.total_sections == 2
    assert report.review_retries == 0


@pytest.mark.asyncio
async def test_markdown_files_written_to_workspace(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=2))

    await run(contract, llm_provider=provider)

    narrative = Path(contract.workspace) / "narrative.md"
    summary = Path(contract.workspace) / "executive_summary.md"
    assert narrative.exists()
    assert summary.exists()
    assert "# Synthesis Narrative" in narrative.read_text()
    assert "# Executive Summary" in summary.read_text()
    assert "Section 1" in narrative.read_text()
    assert "Section 2" in narrative.read_text()


@pytest.mark.asyncio
async def test_run_id_and_customer_id_propagate_from_contract(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=1))

    report = await run(contract, llm_provider=provider)

    assert report.run_id == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    assert report.customer_id == "acme"


@pytest.mark.asyncio
async def test_cited_finding_ids_deduplicated_across_sections(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    outline = json.dumps(
        {
            "overall_narrative_intent": "Cover the findings.",
            "sections": [
                {
                    "heading": "Section 1",
                    "intent": "x",
                    "cited_finding_ids": ["CSPM-A", "CSPM-B"],
                },
                {
                    "heading": "Section 2",
                    "intent": "y",
                    "cited_finding_ids": ["CSPM-B", "CSPM-C"],  # B repeats
                },
            ],
        }
    )
    provider = FakeLLMProvider(
        [_resp(outline), _resp("Body 1"), _resp("Body 2"), _resp(_exec_summary_json())]
    )

    report = await run(contract, llm_provider=provider)
    assert report.cited_finding_ids == ["CSPM-A", "CSPM-B", "CSPM-C"]
    assert report.total_cited_findings == 3


# ---------------------------------------------------------------------------
# Q6 retry loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_q6_retry_succeeds_on_second_pass(tmp_path: Path) -> None:
    """First narrate yields SSN-leaking body; reviewer flags Q6;
    retry yields clean body."""
    contract = _contract(tmp_path)
    leak_outline = _outline_json(sections=1)
    responses = [
        _resp(leak_outline),
        _resp("Bucket contained 123-45-6789 — an SSN."),  # Q6 leak
        _resp(_exec_summary_json()),
        # Retry pass:
        _resp(leak_outline),
        _resp("Bucket contained classified `ssn` data."),  # clean
        _resp(_exec_summary_json()),
    ]
    provider = FakeLLMProvider(responses)

    report = await run(contract, llm_provider=provider)

    assert report.review_retries == 1
    # Second pass body, not first
    assert "123-45-6789" not in report.sections[0].body


@pytest.mark.asyncio
async def test_q6_retry_budget_exhausted_accepts_degraded(tmp_path: Path) -> None:
    """Q6 violation persists across both passes; driver accepts the
    degraded draft (review_retries=1) and logs a warning."""
    contract = _contract(tmp_path)
    leak_outline = _outline_json(sections=1)
    responses = [
        _resp(leak_outline),
        _resp("Bucket contained 123-45-6789 — an SSN."),
        _resp(_exec_summary_json()),
        # Retry still leaks
        _resp(leak_outline),
        _resp("Still leaking 987-65-4321 — another SSN."),
        _resp(_exec_summary_json()),
    ]
    provider = FakeLLMProvider(responses)

    report = await run(contract, llm_provider=provider)

    assert report.review_retries == 1
    # Driver still wrote the markdown files (degraded but legal).
    narrative = Path(contract.workspace) / "narrative.md"
    assert narrative.exists()


# ---------------------------------------------------------------------------
# Narrator failure / fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_outline_call_error_emits_fallback_narrative(tmp_path: Path) -> None:
    """Malformed outline JSON -> fallback narrative section."""
    contract = _contract(tmp_path)
    cp_ws = _write_workspace_findings(tmp_path / "cspm", [_stub_finding("CSPM-1")])
    provider = FakeLLMProvider([_resp("not JSON at all")])

    report = await run(contract, llm_provider=provider, cloud_posture_workspace=cp_ws)

    assert report.total_sections == 1
    assert report.sections[0].heading == "Synthesis failed"
    assert (
        "1" in report.executive_summary.paragraph
        or "findings" in report.executive_summary.paragraph
    )


@pytest.mark.asyncio
async def test_executive_summary_error_emits_fallback(tmp_path: Path) -> None:
    """Outline + per-section succeed; exec summary fails -> fallback."""
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(
        [
            _resp(_outline_json(1)),
            _resp("Section 1 body"),
            _resp("malformed exec summary"),
        ]
    )

    report = await run(contract, llm_provider=provider)

    # Fallback path engaged; outline came back fine but exec summary
    # bombed -> the whole draft is fallback shape.
    assert report.sections[0].heading == "Synthesis failed"


# ---------------------------------------------------------------------------
# Missing / partial workspaces
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_workspaces_still_runs(tmp_path: Path) -> None:
    """All 3 sibling workspaces None -> 0 findings, narrative still emitted."""
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=1))

    report = await run(contract, llm_provider=provider)
    assert report.total_sections == 1


@pytest.mark.asyncio
async def test_partial_workspaces_tolerated(tmp_path: Path) -> None:
    """Only one of three workspaces provided -> driver runs cleanly."""
    contract = _contract(tmp_path)
    cp_ws = _write_workspace_findings(tmp_path / "cspm", [_stub_finding("CSPM-1")])
    provider = FakeLLMProvider(_clean_responses(outline_sections=1))

    report = await run(
        contract,
        llm_provider=provider,
        cloud_posture_workspace=cp_ws,
        compliance_workspace=None,
        investigation_workspace=None,
    )
    assert report.total_sections == 1


# ---------------------------------------------------------------------------
# Knowledge-graph upsert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kg_upsert_skipped_when_semantic_store_none(tmp_path: Path) -> None:
    """Q5 single-tenant default: no kg upsert when store=None."""
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=1))

    await run(contract, llm_provider=provider, semantic_store=None)
    # Nothing to assert about a non-call; just ensure run() completes.


@pytest.mark.asyncio
async def test_kg_upsert_called_when_semantic_store_present(tmp_path: Path) -> None:
    """semantic_store=<mocked> -> KnowledgeGraphWriter.upsert called."""
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=2))
    store = _make_semantic_store()

    await run(contract, llm_provider=provider, semantic_store=store)

    store.upsert_entity.assert_awaited_once()
    call = store.upsert_entity.await_args.kwargs
    assert call["entity_type"] == "synthesis_report"
    assert call["external_id"] == "acme:01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    assert call["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_kg_upsert_carries_section_count_and_summary(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=3))
    store = _make_semantic_store()

    await run(contract, llm_provider=provider, semantic_store=store)

    props = store.upsert_entity.await_args.kwargs["properties"]
    assert props["section_count"] == 3
    assert "scan window" in props["executive_summary_paragraph"].lower()


# ---------------------------------------------------------------------------
# Markdown content sanity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_narrative_md_carries_cited_findings(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    outline = json.dumps(
        {
            "overall_narrative_intent": "x",
            "sections": [
                {
                    "heading": "IAM",
                    "intent": "y",
                    "cited_finding_ids": ["CSPM-IAM-1", "CSPM-IAM-2"],
                }
            ],
        }
    )
    provider = FakeLLMProvider([_resp(outline), _resp("IAM body."), _resp(_exec_summary_json())])

    await run(contract, llm_provider=provider)
    narrative = (Path(contract.workspace) / "narrative.md").read_text()
    assert "CSPM-IAM-1" in narrative
    assert "CSPM-IAM-2" in narrative


@pytest.mark.asyncio
async def test_executive_summary_md_carries_key_metrics(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    provider = FakeLLMProvider(_clean_responses(outline_sections=1))

    await run(contract, llm_provider=provider)
    summary = (Path(contract.workspace) / "executive_summary.md").read_text()
    assert "Key Metrics" in summary
    assert "total_findings" in summary
    assert "top_failing_control" in summary
