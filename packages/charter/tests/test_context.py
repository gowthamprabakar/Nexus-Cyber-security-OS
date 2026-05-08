"""Tests for the Charter context manager — the public wrapper."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import Charter, ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from charter.exceptions import BudgetExhausted, ToolNotPermitted


def _make_contract(tmp_path: Path, *, llm_calls: int = 5, tokens: int = 1000) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="hello_world",
        customer_id="cust_test",
        task="say hi",
        required_outputs=["greeting.txt"],
        budget=BudgetSpec(
            llm_calls=llm_calls,
            tokens=tokens,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["echo"],
        completion_condition="greeting.txt exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("echo", lambda value: value, version="1.0.0", cloud_calls=0)
    reg.register("delete", lambda: None, version="1.0.0", cloud_calls=1)
    return reg


def test_context_runs_simple_tool(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        result = ctx.call_tool("echo", value="hi", llm_calls=1, tokens=10)
        assert result == "hi"
        ctx.write_output("greeting.txt", b"hi")


def test_context_rejects_unpermitted_tool(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx, pytest.raises(ToolNotPermitted):
        ctx.call_tool("delete", llm_calls=0, tokens=0)


def test_context_enforces_budget(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path, llm_calls=2)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.call_tool("echo", value="a", llm_calls=1, tokens=10)
        ctx.call_tool("echo", value="b", llm_calls=1, tokens=10)
        with pytest.raises(BudgetExhausted) as exc_info:
            ctx.call_tool("echo", value="c", llm_calls=1, tokens=10)
        assert exc_info.value.dimension == "llm_calls"


def test_context_writes_audit_log(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.call_tool("echo", value="hi", llm_calls=1, tokens=10)
        ctx.write_output("greeting.txt", b"hi")
        audit_path = ctx.audit_path
    assert audit_path.exists()
    lines = audit_path.read_text().strip().split("\n")
    actions = [line for line in lines if "tool_call" in line or "output_written" in line]
    assert len(actions) >= 2  # tool_call + output_written


def test_context_completion_check(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        # Don't write the required output.
        with pytest.raises(RuntimeError) as exc_info:
            ctx.assert_complete()
        assert "greeting.txt" in str(exc_info.value)


def test_context_assert_complete_passes_when_outputs_present(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.write_output("greeting.txt", b"hi")
        ctx.assert_complete()  # does not raise
