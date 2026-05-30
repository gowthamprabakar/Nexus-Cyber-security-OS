"""Tests for ExecutionContract."""

from datetime import UTC, datetime, timedelta
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


# ---------------------------------------------------------------------------
# G2 Task 2 — trigger_source field (SAFETY-CRITICAL, charter substrate)
# ---------------------------------------------------------------------------


def _valid_contract_kwargs() -> dict:
    """Return kwargs for a minimal valid ExecutionContract."""
    return {
        "schema_version": "0.1",
        "delegation_id": "01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        "source_agent": "supervisor",
        "target_agent": "cloud_posture",
        "customer_id": "cust_acme_001",
        "task": "scan",
        "required_outputs": ["findings.json"],
        "budget": {
            "llm_calls": 1,
            "tokens": 1,
            "wall_clock_sec": 1,
            "cloud_api_calls": 1,
            "mb_written": 1,
        },
        "permitted_tools": ["prowler_scan"],
        "completion_condition": "x",
        "workspace": "/workspaces/x/",
        "persistent_root": "/persistent/x/",
        "created_at": datetime.now(UTC) - timedelta(hours=1),
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
    }


def test_trigger_source_defaults_to_none() -> None:
    """Backwards-compat — contracts without trigger_source default to None."""
    contract = ExecutionContract(**_valid_contract_kwargs())
    assert contract.trigger_source is None


def test_trigger_source_accepts_valid_values() -> None:
    """All three TriggerSource enum values pass validation."""
    for value in ("events_bus", "operator_cli", "scheduled_queue"):
        kwargs = _valid_contract_kwargs()
        kwargs["trigger_source"] = value
        contract = ExecutionContract(**kwargs)
        assert contract.trigger_source == value


def test_trigger_source_rejects_invalid_value() -> None:
    """Validator rejects strings outside the TriggerSource value space."""
    kwargs = _valid_contract_kwargs()
    kwargs["trigger_source"] = "random_value"
    with pytest.raises(ValidationError):
        ExecutionContract(**kwargs)


def test_trigger_source_serialization_round_trip() -> None:
    """trigger_source survives model_dump / model_validate round-trip."""
    kwargs = _valid_contract_kwargs()
    kwargs["trigger_source"] = "events_bus"
    contract = ExecutionContract(**kwargs)
    dumped = contract.model_dump()
    reloaded = ExecutionContract.model_validate(dumped)
    assert reloaded.trigger_source == "events_bus"


def test_trigger_source_json_deserialization_absent() -> None:
    """JSON without trigger_source field → trigger_source is None."""
    kwargs = _valid_contract_kwargs()
    contract = ExecutionContract(**kwargs)
    dumped = contract.model_dump()
    del dumped["trigger_source"]
    reloaded = ExecutionContract.model_validate(dumped)
    assert reloaded.trigger_source is None


def test_trigger_source_json_deserialization_present() -> None:
    """JSON with trigger_source field → correct string value."""
    kwargs = _valid_contract_kwargs()
    kwargs["trigger_source"] = "scheduled_queue"
    contract = ExecutionContract(**kwargs)
    dumped = contract.model_dump()
    reloaded = ExecutionContract.model_validate(dumped)
    assert reloaded.trigger_source == "scheduled_queue"


def test_trigger_source_existing_contract_still_validates() -> None:
    """Existing contract fixtures (no trigger_source) still pass validation."""
    from charter.contract import load_contract

    contract = load_contract(FIXTURES / "valid_contract.yaml")
    # Existing fixture has no trigger_source — must default to None.
    assert contract.trigger_source is None
    # All other fields still parse correctly.
    assert contract.target_agent == "cloud_posture"
