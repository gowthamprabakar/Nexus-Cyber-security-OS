"""Eval trace model + parser — captures what happened during a single case run.

`build_trace_from_audit_log` parses a charter-emitted `audit.jsonl` into
the typed `EvalTrace` model and verifies the hash chain via
`charter.verifier.verify_audit_log`. Lives in the eval framework so
Meta-Harness (A.4) can read this shape directly without having to
interpret raw audit-log JSON.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from charter.verifier import verify_audit_log
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


# ---------------------------- Parser ---------------------------------------


def _parse_iso_z(ts: str) -> datetime:
    """Parse charter audit timestamps (ISO-8601 with trailing 'Z')."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def build_trace_from_audit_log(audit_log_path: Path | str) -> EvalTrace:
    """Parse a charter audit.jsonl and return a populated `EvalTrace`.

    - Pairs `llm_call_started` ↔ `llm_call_completed` in order to recover
      input/output token counts and a per-call `duration_sec`. Unpaired
      starts (e.g., crash mid-call, or a matching `llm_call_failed`) are
      dropped — they have no token accounting.
    - `tool_call` becomes a `ToolCallRecord` (`duration_sec=0.0` until the
      charter starts emitting per-call duration).
    - `output_written` becomes an `OutputWriteRecord`.
    - The hash chain is verified via `charter.verifier.verify_audit_log`;
      `audit_chain_valid` reflects the verifier's result. A missing file
      yields `audit_chain_valid=False` with empty record lists.
    - Malformed JSON lines are skipped (the verifier will mark the chain
      invalid; the parser stays resilient).
    """
    p = Path(audit_log_path)
    path_str = str(p)

    if not p.exists():
        return EvalTrace(audit_log_path=path_str, audit_chain_valid=False)

    # The verifier raises on malformed JSON / bad shape; treat that as an
    # invalid chain rather than letting the exception escape.
    try:
        chain_valid = verify_audit_log(p).valid
    except (json.JSONDecodeError, TypeError, ValueError):
        chain_valid = False

    llm_calls: list[LLMCallRecord] = []
    tool_calls: list[ToolCallRecord] = []
    output_writes: list[OutputWriteRecord] = []
    pending_started: dict[str, Any] | None = None

    with p.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # verifier already flagged the chain
            action = entry.get("action")
            payload = entry.get("payload") or {}
            timestamp = entry.get("timestamp", "")

            if action == "tool_call":
                tool_calls.append(
                    ToolCallRecord(
                        tool=str(payload.get("tool", "")),
                        version=str(payload.get("version", "")),
                        duration_sec=0.0,
                    )
                )
            elif action == "output_written":
                output_writes.append(
                    OutputWriteRecord(
                        name=str(payload.get("name", "")),
                        bytes_written=int(payload.get("bytes", 0)),
                    )
                )
            elif action == "llm_call_started":
                pending_started = {"timestamp": timestamp, "payload": payload}
            elif action == "llm_call_completed" and pending_started is not None:
                started_ts = _parse_iso_z(str(pending_started["timestamp"]))
                completed_ts = _parse_iso_z(timestamp)
                duration = max(0.0, (completed_ts - started_ts).total_seconds())
                llm_calls.append(
                    LLMCallRecord(
                        provider_id=str(payload.get("provider_id", "")),
                        model_pin=str(payload.get("model_pin", "")),
                        input_tokens=int(payload.get("input_tokens", 0)),
                        output_tokens=int(payload.get("output_tokens", 0)),
                        stop_reason=str(payload.get("stop_reason", "")),
                        started_at=started_ts,
                        duration_sec=duration,
                    )
                )
                pending_started = None
            elif action == "llm_call_failed":
                # Failed call: drop the pending start; no token record exists.
                pending_started = None

    return EvalTrace(
        audit_log_path=path_str,
        llm_calls=llm_calls,
        tool_calls=tool_calls,
        output_writes=output_writes,
        audit_chain_valid=chain_valid,
    )
