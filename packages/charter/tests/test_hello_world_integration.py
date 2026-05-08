"""Integration test: run the hello-world agent end-to-end through the charter."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from charter.contract import BudgetSpec, ExecutionContract
from charter.examples.hello_world_agent.agent import run
from charter.verifier import verify_audit_log


def test_hello_world_runs_end_to_end(tmp_path: Path) -> None:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="hello_world",
        customer_id="cust_test",
        task="say hi to the integration test",
        required_outputs=["greeting.txt"],
        budget=BudgetSpec(
            llm_calls=5, tokens=500, wall_clock_sec=30.0, cloud_api_calls=5, mb_written=1
        ),
        permitted_tools=["echo"],
        completion_condition="greeting.txt exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    path = run(contract)
    assert path.exists()
    assert b"say hi to the integration test" in path.read_bytes()

    audit_path = Path(contract.workspace) / "audit.jsonl"
    result = verify_audit_log(audit_path)
    assert result.valid is True
    assert (
        result.entries_checked >= 4
    )  # invocation_started, tool_call, output_written, invocation_completed
