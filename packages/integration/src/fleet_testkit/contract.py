"""Wiring ``ExecutionContract`` builder for fleet-test harnesses."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from charter.contract import BudgetSpec, ExecutionContract

# A valid ULID shape (26 Crockford-base32 chars) — the delegation/run id.
_DEFAULT_DELEGATION_ID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


def wiring_contract(
    tmp_path: Path,
    *,
    target_agent: str,
    permitted_tools: Sequence[str],
    customer_id: str = "cust_test",
    delegation_id: str = _DEFAULT_DELEGATION_ID,
    cloud_api_calls: int = 100_000,
) -> ExecutionContract:
    """Build an ``ExecutionContract`` for an L1 wiring test.

    Workspace + persistent root derive from ``tmp_path`` — pass distinct paths (and
    ``customer_id``) per tenant for the two-tenant isolation run.
    """
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id,
        source_agent="supervisor",
        target_agent=target_agent,
        customer_id=customer_id,
        task=f"fleet-test L1 wiring smoke for {target_agent}",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=cloud_api_calls,
            mb_written=10,
        ),
        permitted_tools=list(permitted_tools),
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
