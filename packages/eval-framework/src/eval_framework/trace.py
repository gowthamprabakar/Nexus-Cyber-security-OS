"""Eval trace model — captures what happened during a single case run.

Built by `eval_framework.trace.build_trace_from_audit_log` (lands in F.2
Task 6) by parsing a charter-emitted `audit.jsonl`. Lives in the eval
framework so Meta-Harness (A.4) can read this shape directly without
having to interpret raw audit-log JSON.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LLMCallRecord(BaseModel):
    """One LLM call. Paired from `llm_call_started` + `llm_call_completed`."""

    provider_id: str
    model_pin: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    stop_reason: str
    started_at: datetime
    duration_sec: float = Field(ge=0.0)

    model_config = ConfigDict(frozen=True)


class ToolCallRecord(BaseModel):
    """One tool call through the charter (e.g. prowler_scan, aws_s3_describe)."""

    tool: str
    version: str
    duration_sec: float = Field(ge=0.0)

    model_config = ConfigDict(frozen=True)


class OutputWriteRecord(BaseModel):
    """One charter-written output (e.g. findings.json, summary.md)."""

    name: str
    bytes_written: int = Field(ge=0)

    model_config = ConfigDict(frozen=True)


class EvalTrace(BaseModel):
    """What happened during one case run, parsed from the charter audit log."""

    audit_log_path: str | None = None
    llm_calls: list[LLMCallRecord] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    output_writes: list[OutputWriteRecord] = Field(default_factory=list)
    audit_chain_valid: bool | None = None

    model_config = ConfigDict(frozen=True)
