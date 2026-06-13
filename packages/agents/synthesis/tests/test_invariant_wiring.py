"""Phase C SS5 — D.13 synthesis LLM invariants are load-bearing in run().

Cycle 13 defined assert_categorical_only (WI-Y8), assert_bounded_retry (WI-Y10), and
assert_findings_cited (WI-Y13) but never called them from run(). These tests prove the Phase C
wiring: a happy-path run invokes all three, and the hard-fail paths are covered by
test_agent_unit (plaintext-PII degraded draft) + test_hallucination_guard.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import synthesis.agent as agent_mod
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from synthesis.agent import run


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
            llm_calls=20, tokens=50_000, wall_clock_sec=120.0, cloud_api_calls=1, mb_written=10
        ),
        permitted_tools=["read_sibling_workspaces"],
        completion_condition="narrative.md AND executive_summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=100, output_tokens=50),
        model_pin="claude-haiku-4-5-20251001",
    )


def _clean_responses() -> list[LLMResponse]:
    outline = json.dumps(
        {
            "overall_narrative_intent": "Cover the findings.",
            "sections": [
                {"heading": "S1", "intent": "Intent", "cited_finding_ids": ["CSPM-AWS-001"]}
            ],
        }
    )
    exec_summary = json.dumps(
        {
            "paragraph": "The scan window surfaced findings of mixed severity for review.",
            "key_metrics": {
                "total_findings": 1,
                "critical": 0,
                "high": 1,
                "top_failing_control": "1.10",
            },
        }
    )
    return [
        _resp(outline),
        _resp("Body of section one — operator-grade prose."),
        _resp(exec_summary),
    ]


def _write_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "cspm"
    ws.mkdir(parents=True, exist_ok=True)
    finding: dict[str, Any] = {
        "class_uid": 2003,
        "severity_id": 4,
        "finding_info": {"uid": "CSPM-AWS-001", "title": "Finding"},
    }
    (ws / "findings.json").write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
    return ws


@pytest.mark.asyncio
async def test_run_invokes_all_three_llm_invariants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    real_cat = agent_mod.assert_categorical_only
    real_retry = agent_mod.assert_bounded_retry
    real_cite = agent_mod.assert_findings_cited

    def spy_cat(text: str) -> None:
        calls.append("categorical")
        real_cat(text)

    def spy_retry(n: int) -> None:
        calls.append("bounded_retry")
        real_retry(n)

    def spy_cite(narrative: str, source: set[str]) -> None:
        calls.append("findings_cited")
        real_cite(narrative, source)

    monkeypatch.setattr(agent_mod, "assert_categorical_only", spy_cat)
    monkeypatch.setattr(agent_mod, "assert_bounded_retry", spy_retry)
    monkeypatch.setattr(agent_mod, "assert_findings_cited", spy_cite)

    await run(
        _contract(tmp_path),
        llm_provider=FakeLLMProvider(_clean_responses()),
        cloud_posture_workspace=_write_workspace(tmp_path),
    )

    assert "bounded_retry" in calls
    assert "findings_cited" in calls
    # categorical_only guards both the narrative + the executive summary.
    assert calls.count("categorical") >= 2
