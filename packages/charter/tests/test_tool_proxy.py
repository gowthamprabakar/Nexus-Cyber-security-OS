"""Tests for the tool-proxy hard boundary (ADR-016 Mechanisms 1 & 3).

The registry wraps each tool in a proxy that runs the underlying callable only
inside a charter-mediated dispatch; any other invocation raises
DirectInvocationBlocked. forbidden_tools is validated at contract level and
checked first in ctx.call_tool.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from charter import (
    Charter,
    DirectInvocationBlocked,
    ToolForbidden,
    ToolNotPermitted,
    ToolRegistry,
)
from charter.contract import BudgetSpec, ExecutionContract
from charter.tools import _IN_DISPATCH, _ProxiedTool


def _make_contract(
    tmp_path: Path,
    *,
    permitted: list[str] | None = None,
    forbidden: list[str] | None = None,
) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="proxy_test",
        customer_id="cust_test",
        task="exercise proxy",
        required_outputs=["out.txt"],
        budget=BudgetSpec(
            llm_calls=5, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=permitted or ["echo"],
        forbidden_tools=forbidden or [],
        completion_condition="out.txt exists",
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


# --- Mechanism 1: runtime proxy ---------------------------------------------


def test_registered_callable_blocks_direct_invocation() -> None:
    """The registry-held proxy cannot run outside a dispatch."""
    reg = _registry()
    proxy = reg._tools["echo"].proxy
    with pytest.raises(DirectInvocationBlocked) as exc:
        proxy(value="hi")
    assert exc.value.tool == "echo"


def test_registry_call_dispatches_successfully() -> None:
    reg = _registry()
    assert reg.call("echo", permitted=["echo"], value="hi") == "hi"


def test_flag_is_false_outside_dispatch() -> None:
    assert _IN_DISPATCH.get() is False


def test_flag_reset_after_successful_dispatch() -> None:
    reg = _registry()
    reg.call("echo", permitted=["echo"], value="hi")
    assert _IN_DISPATCH.get() is False
    # A subsequent direct call still raises (flag did not leak True).
    with pytest.raises(DirectInvocationBlocked):
        reg._tools["echo"].proxy(value="x")


def test_flag_reset_after_tool_raises() -> None:
    reg = ToolRegistry()

    def boom(**_: object) -> None:
        raise ValueError("kaboom")

    reg.register("boom", boom, version="1.0.0", cloud_calls=0)
    with pytest.raises(ValueError, match="kaboom"):
        reg.call("boom", permitted=["boom"])
    assert _IN_DISPATCH.get() is False


def test_charter_call_tool_gated_path_works(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        assert ctx.call_tool("echo", value="hi") == "hi"


def test_unpermitted_still_raises_inside_dispatch() -> None:
    reg = _registry()
    with pytest.raises(ToolNotPermitted):
        reg.call("delete", permitted=["echo"])


def test_unknown_tool_raises_keyerror() -> None:
    reg = _registry()
    with pytest.raises(KeyError):
        reg.call("ghost", permitted=["ghost"])


def test_metadata_survives_proxy_wrapping() -> None:
    reg = _registry()
    assert reg.version("echo") == "1.0.0"
    assert reg.cloud_calls("delete") == 1
    assert reg.known_tools() == ["delete", "echo"]


def test_duplicate_registration_still_rejected() -> None:
    reg = ToolRegistry()
    reg.register("x", lambda: None, version="1.0.0", cloud_calls=0)
    with pytest.raises(ValueError, match="already registered"):
        reg.register("x", lambda: None, version="1.0.0", cloud_calls=0)


# --- async tools: guard fires at coroutine-creation time --------------------


def test_async_tool_gated_dispatch_works() -> None:
    reg = ToolRegistry()

    async def aecho(value: str) -> str:
        await asyncio.sleep(0)
        return value

    reg.register("aecho", aecho, version="1.0.0", cloud_calls=0)

    async def run() -> str:
        return await reg.call("aecho", permitted=["aecho"], value="hi")

    assert asyncio.run(run()) == "hi"


def test_async_tool_direct_invocation_blocked() -> None:
    reg = ToolRegistry()

    async def aecho(value: str) -> str:
        return value

    reg.register("aecho", aecho, version="1.0.0", cloud_calls=0)
    proxy = reg._tools["aecho"].proxy
    # The guard fires synchronously when the coroutine is *created*, before await.
    with pytest.raises(DirectInvocationBlocked):
        proxy(value="hi")


def test_concurrent_dispatch_each_gated() -> None:
    reg = ToolRegistry()

    async def aecho(value: str) -> str:
        await asyncio.sleep(0)
        return value

    reg.register("aecho", aecho, version="1.0.0", cloud_calls=0)

    async def run() -> list[str]:
        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(reg.call("aecho", permitted=["aecho"], value=str(i)))
                for i in range(5)
            ]
        return [t.result() for t in tasks]

    assert asyncio.run(run()) == ["0", "1", "2", "3", "4"]
    assert _IN_DISPATCH.get() is False


def test_proxy_repr_exposes_name() -> None:
    p = _ProxiedTool("mytool", lambda: None)
    assert p.name == "mytool"


# --- Mechanism 3: forbidden_tools -------------------------------------------


def test_forbidden_tool_call_raises(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path, permitted=["echo"], forbidden=["delete"])
    with Charter(contract, tools=_registry()) as ctx, pytest.raises(ToolForbidden) as exc:
        ctx.call_tool("delete")
    assert exc.value.tool == "delete"


def test_forbidden_checked_before_budget(tmp_path: Path) -> None:
    """A forbidden call must not consume budget."""
    contract = _make_contract(tmp_path, permitted=["echo"], forbidden=["delete"])
    with Charter(contract, tools=_registry()) as ctx:
        before = ctx.budget.remaining("cloud_api_calls")
        with pytest.raises(ToolForbidden):
            ctx.call_tool("delete")
        assert ctx.budget.remaining("cloud_api_calls") == before


def test_contract_rejects_forbidden_permitted_overlap(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not overlap"):
        _make_contract(tmp_path, permitted=["echo", "delete"], forbidden=["delete"])


def test_contract_defaults_forbidden_to_empty(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    assert contract.forbidden_tools == []
