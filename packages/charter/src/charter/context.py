"""Charter context manager — the public wrapper around an agent invocation."""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import Any

from charter.audit import AuditLog
from charter.budget import BudgetEnvelope
from charter.contract import ExecutionContract
from charter.tools import ToolRegistry
from charter.workspace import WorkspaceManager


class Charter:
    """Wraps a single agent invocation under the runtime charter.

    Usage:
        with Charter(contract, tools=registry) as ctx:
            ctx.call_tool("prowler_scan", ...)
            ctx.write_output("findings.json", data)
            ctx.assert_complete()
    """

    def __init__(self, contract: ExecutionContract, tools: ToolRegistry) -> None:
        self.contract = contract
        self.tools = tools
        self.budget = BudgetEnvelope(
            llm_calls=contract.budget.llm_calls,
            tokens=contract.budget.tokens,
            wall_clock_sec=contract.budget.wall_clock_sec,
            cloud_api_calls=contract.budget.cloud_api_calls,
            mb_written=contract.budget.mb_written,
        )
        self.workspace_mgr = WorkspaceManager(
            workspace=Path(contract.workspace),
            persistent_root=Path(contract.persistent_root),
        )
        self.audit_path = Path(contract.workspace) / "audit.jsonl"
        self.audit: AuditLog | None = None

    def __enter__(self) -> Charter:
        self.workspace_mgr.setup()
        self.audit = AuditLog(
            path=self.audit_path,
            agent=self.contract.target_agent,
            run_id=self.contract.delegation_id,
        )
        self.audit.append(action="invocation_started", payload={"task": self.contract.task})
        self.budget.start_clock()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.audit is None:
            raise RuntimeError("Charter.__exit__ called before __enter__")
        if exc is None:
            self.audit.append(action="invocation_completed", payload={})
        else:
            self.audit.append(
                action="invocation_failed",
                payload={"exception": exc.__class__.__name__, "message": str(exc)},
            )

    def call_tool(self, name: str, *, llm_calls: int = 0, tokens: int = 0, **kwargs: Any) -> Any:
        """Run a tool through the charter — whitelist + budget + audit."""
        if self.audit is None:
            raise RuntimeError("call_tool called outside of Charter context manager")
        self.budget.check_wall_clock()
        cloud_calls = self.tools.cloud_calls(name) if name in self.tools.known_tools() else 0
        self.budget.consume(llm_calls=llm_calls, tokens=tokens, cloud_api_calls=cloud_calls)
        self.audit.append(
            action="tool_call",
            payload={
                "tool": name,
                "version": self.tools.version(name)
                if name in self.tools.known_tools()
                else "unknown",
                "kwargs_keys": sorted(kwargs.keys()),
            },
        )
        return self.tools.call(name, permitted=self.contract.permitted_tools, **kwargs)

    def write_output(self, name: str, data: bytes) -> Path:
        if self.audit is None:
            raise RuntimeError("write_output called outside of Charter context manager")
        self.budget.consume(mb_written=len(data) / 1_048_576)  # bytes → MB
        path = self.workspace_mgr.write_output(name, data)
        self.audit.append(action="output_written", payload={"name": name, "bytes": len(data)})
        return path

    def assert_complete(self) -> None:
        missing = self.workspace_mgr.missing_outputs(self.contract.required_outputs)
        if missing:
            raise RuntimeError(f"required outputs missing: {missing}")
