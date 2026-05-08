"""Hello-world reference agent — demonstrates Charter pipeline end-to-end."""

from __future__ import annotations

from pathlib import Path

from charter import Charter, ExecutionContract, ToolRegistry, load_contract

from .tools import echo


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("echo", echo, version="1.0.0", cloud_calls=0)
    return reg


def run(contract: ExecutionContract) -> Path:
    """Run the hello-world agent under the charter. Returns the greeting path."""
    registry = build_registry()
    with Charter(contract, tools=registry) as ctx:
        greeting = ctx.call_tool(
            "echo", value=f"Hello — task was: {contract.task}", llm_calls=1, tokens=20
        )
        path = ctx.write_output("greeting.txt", greeting.encode("utf-8"))
        ctx.assert_complete()
    return path


def run_from_file(contract_path: Path) -> Path:
    return run(load_contract(contract_path))
