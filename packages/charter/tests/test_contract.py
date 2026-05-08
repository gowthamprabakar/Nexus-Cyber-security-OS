"""Tests for ExecutionContract."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.contract import ExecutionContract, load_contract
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_valid_contract() -> None:
    contract = load_contract(FIXTURES / "valid_contract.yaml")
    assert contract.target_agent == "cloud_posture"
    assert contract.budget.llm_calls == 20
    assert "findings.json" in contract.required_outputs


def test_load_invalid_contract_raises() -> None:
    with pytest.raises(ValidationError):
        load_contract(FIXTURES / "invalid_contract.yaml")


def test_contract_rejects_blank_task() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="",
            required_outputs=["findings.json"],
            budget={
                "llm_calls": 1,
                "tokens": 1,
                "wall_clock_sec": 1,
                "cloud_api_calls": 1,
                "mb_written": 1,
            },
            permitted_tools=["prowler_scan"],
            completion_condition="findings.json exists",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )


def test_contract_requires_at_least_one_output() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="scan",
            required_outputs=[],
            budget={
                "llm_calls": 1,
                "tokens": 1,
                "wall_clock_sec": 1,
                "cloud_api_calls": 1,
                "mb_written": 1,
            },
            permitted_tools=["prowler_scan"],
            completion_condition="x",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )


def test_contract_requires_at_least_one_tool() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="scan",
            required_outputs=["findings.json"],
            budget={
                "llm_calls": 1,
                "tokens": 1,
                "wall_clock_sec": 1,
                "cloud_api_calls": 1,
                "mb_written": 1,
            },
            permitted_tools=[],
            completion_condition="x",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )
