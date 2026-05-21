"""Live-LLM smoke test for D.13 Synthesis (Task 14).

**Skipped by default.** Enable with:

    NEXUS_LIVE_LLM=1 \
        NEXUS_LLM_PROVIDER=anthropic \
        NEXUS_LLM_MODEL_PIN=claude-haiku-4-5-20251001 \
        ANTHROPIC_API_KEY=... \
        uv run pytest \
        packages/agents/synthesis/tests/integration/test_live_llm_smoke.py -v

**What this lane proves (and why it exists).**

Tasks 1-13 ship the agent + the deterministic stub-LLM eval suite.
Those prove the **contract** — pipeline plumbing, schema validation,
Q6 retry loop, byte-equal stub-LLM determinism. They do NOT prove
that the agent works against a **real** LLM provider end-to-end:
that the prompt templates are good enough to elicit valid JSON +
operator-grade prose, that the model_pin is reachable, that the
charter.llm_adapter budget consumption fires, that real-world
outputs pass the deterministic reviewer.

This is D.13 v0.1's WI-1 acceptance gate (first LLM-call agent in
the fleet — verify the actual LLM call works).

**Acceptance.** The single test in this module passes in one
``NEXUS_LIVE_LLM=1`` run, against any configured live provider. CI
skips it; operator-side smoke verification runs it.

**Assertions are shape, not byte-equal.** The live LLM is non-
deterministic; we assert that the report has at least one section,
a non-empty executive-summary paragraph, no Q6 retries (since v0.1
prompts are tuned to avoid leakage), and that the markdown files
landed in the workspace.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm_adapter import config_from_env, make_provider
from synthesis.agent import run as agent_run

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_LLM") == "1"


def _provider_configured() -> tuple[bool, str]:
    """Pre-flight check that NEXUS_LLM_* env vars are set."""
    if not os.environ.get("NEXUS_LLM_PROVIDER"):
        return False, "NEXUS_LLM_PROVIDER not set"
    if not os.environ.get("NEXUS_LLM_MODEL_PIN"):
        return False, "NEXUS_LLM_MODEL_PIN not set"
    return True, ""


_TOOLING_OK, _TOOLING_REASON = (
    (False, "live LLM tests disabled (set NEXUS_LIVE_LLM=1)")
    if not _live_enabled()
    else _provider_configured()
)

pytestmark.append(
    pytest.mark.skipif(
        not _TOOLING_OK,
        reason=(
            f"set NEXUS_LIVE_LLM=1 + ensure NEXUS_LLM_PROVIDER + "
            f"NEXUS_LLM_MODEL_PIN are configured "
            f"(and the relevant API key env var like ANTHROPIC_API_KEY); "
            f"current status: {_TOOLING_REASON}. See module docstring."
        ),
    )
)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="synthesis",
        customer_id="cust_live_smoke",
        task="Synthesis live-LLM smoke",
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


def _write_workspace(path: Path, findings: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    import json

    (path / "findings.json").write_text(
        json.dumps({"findings": findings}, default=str),
        encoding="utf-8",
    )
    return path


async def test_synthesis_runs_against_live_provider(tmp_path: Path) -> None:
    """Happy-path live-LLM smoke.

    Runs the agent end-to-end with a one-finding F.3 fixture; asserts
    SynthesisReport shape correctness + markdown files written +
    no Q6 retries (since v0.1 prompts are tuned to avoid leakage).
    """
    contract = _contract(tmp_path)
    cp_ws = _write_workspace(
        tmp_path / "cspm",
        [
            {
                "class_uid": 2003,
                "severity_id": 4,
                "finding_info": {
                    "uid": "CSPM-AWS-IAM-001",
                    "title": "IAM user missing MFA",
                },
            }
        ],
    )

    provider = make_provider(config_from_env())

    report = await agent_run(
        contract=contract,
        llm_provider=provider,
        cloud_posture_workspace=cp_ws,
    )

    # Shape assertions — live LLM is non-deterministic; we don't
    # byte-compare prose. We assert the contract holds.
    assert report.customer_id == "cust_live_smoke"
    assert report.run_id == contract.delegation_id
    assert report.total_sections >= 1
    assert report.executive_summary.paragraph.strip()
    assert report.executive_summary.key_metrics  # non-empty dict
    assert report.review_retries == 0, (
        f"unexpected Q6 retry on live-LLM smoke: {report.review_retries} (check prompt templates)"
    )

    # Markdown files written to workspace.
    narrative_path = Path(contract.workspace) / "narrative.md"
    summary_path = Path(contract.workspace) / "executive_summary.md"
    assert narrative_path.exists()
    assert summary_path.exists()
    narrative_md = narrative_path.read_text(encoding="utf-8")
    summary_md = summary_path.read_text(encoding="utf-8")
    assert "# Synthesis Narrative" in narrative_md
    assert "# Executive Summary" in summary_md
    # The finding-id should appear somewhere in the rendered narrative
    # (cited_finding_ids flow through from outline -> section -> markdown).
    assert "CSPM-AWS-IAM-001" in narrative_md
