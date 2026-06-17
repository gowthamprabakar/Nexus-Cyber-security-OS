"""Unit tests for the AI-SPM agent driver (D.11 PR1 skeleton)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aispm.agent import build_registry, run
from charter import ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract


class _FakeGarakRunner:
    async def probe(self, *, target: str) -> list[dict]:
        return [{"entry_type": "eval", "probe": "dan", "detector": "dan", "passed": 4, "total": 10}]


class _FakeAwsAiReader:
    def sagemaker_endpoints(self) -> list[dict]:
        return [{"name": "prod", "data_capture_enabled": False, "model_name": "m1"}]

    def sagemaker_notebooks(self) -> list[dict]:
        return []

    def bedrock_logging_enabled(self) -> bool | None:
        return True

    def bedrock_guardrail_count(self) -> int:
        return 1


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="aispm",
        customer_id="cust_test",
        task="AI posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=[
            "discover_aws_ai",
            "discover_azure_ai",
            "discover_gcp_ai",
            "probe_garak",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_build_registry_returns_a_registry() -> None:
    # Empty in PR1; discovery + Garak tools register here in PR2-4.
    assert isinstance(build_registry(), ToolRegistry)


@pytest.mark.asyncio
async def test_empty_run_writes_valid_artifacts(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert report.agent == "aispm"

    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert doc["agent"] == "aispm"
    assert doc["customer_id"] == "cust_test"
    assert doc["findings"] == []

    assert "AI Security Posture" in (tmp_path / "ws" / "summary.md").read_text()


@pytest.mark.asyncio
async def test_semantic_store_default_is_inert(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path), semantic_store=None)
    assert report.total == 0


@pytest.mark.asyncio
async def test_aws_connector_emits_findings(tmp_path: Path) -> None:
    report = await run(
        _contract(tmp_path), aws_account_id="111122223333", aws_reader=_FakeAwsAiReader()
    )
    # data-capture off (1) + no-guardrails would be 0... here logging on, guardrails 1 → only
    # the inference-logging-disabled finding fires.
    assert report.total == 1
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in doc["findings"]}
    assert "aispm_sagemaker_inference_logging_disabled" in types
    assert all(f["class_uid"] == 2003 for f in doc["findings"])


@pytest.mark.asyncio
async def test_probe_default_off_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No probe target + gate unset → no prompt-injection probe (default-off, byte-identical).
    monkeypatch.delenv("NEXUS_LIVE_AISPM_PROBE", raising=False)
    report = await run(_contract(tmp_path), probe_target="bedrock:claude")
    assert report.total == 0  # gate off → garak never runs


@pytest.mark.asyncio
async def test_probe_with_injected_runner_emits_2004(tmp_path: Path) -> None:
    # Injected runner bypasses the env gate (deterministic test path).
    report = await run(
        _contract(tmp_path),
        probe_target="bedrock:claude",
        probe_provider="bedrock",
        garak_runner=_FakeGarakRunner(),
    )
    assert report.total == 1  # dan probe: 6/10 failed → one 2004 detection
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert doc["findings"][0]["class_uid"] == 2004
    assert doc["findings"][0]["finding_info"]["types"][0].startswith("aispm_promptinjection_")
