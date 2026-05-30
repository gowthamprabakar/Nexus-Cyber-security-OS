"""Execution contract — the signed YAML that defines an agent invocation."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


class BudgetSpec(BaseModel):
    """Budget specification — all values must be positive."""

    llm_calls: int = Field(gt=0)
    tokens: int = Field(gt=0)
    wall_clock_sec: float = Field(gt=0)
    cloud_api_calls: int = Field(gt=0)
    mb_written: int = Field(gt=0)


class EscalationRule(BaseModel):
    """When a condition fires, escalate to this target."""

    condition: NonEmptyStr
    target: NonEmptyStr


class ExecutionContract(BaseModel):
    """Signed YAML contract validated by the charter before agent runs.

    Every field is required. A blank/empty value fails validation.
    """

    schema_version: NonEmptyStr
    delegation_id: NonEmptyStr
    source_agent: NonEmptyStr
    target_agent: NonEmptyStr
    customer_id: NonEmptyStr
    task: NonEmptyStr
    required_outputs: list[NonEmptyStr] = Field(min_length=1)
    budget: BudgetSpec
    permitted_tools: list[NonEmptyStr] = Field(min_length=1)
    completion_condition: NonEmptyStr
    escalation_rules: list[EscalationRule] = Field(default_factory=list)
    workspace: NonEmptyStr
    persistent_root: NonEmptyStr
    created_at: datetime
    expires_at: datetime
    trigger_source: str | None = None
    """How this run was triggered. Values: 'events_bus', 'operator_cli',
    'scheduled_queue', or None (legacy contracts predating G2 Task 2).
    Propagated by Supervisor from IncomingTask.trigger_source per G2-Q1
    Option E (dual-mode dispatch).
    """

    @field_validator("trigger_source")
    @classmethod
    def _validate_trigger_source(cls, v: str | None) -> str | None:
        if v is not None and v not in {"events_bus", "operator_cli", "scheduled_queue"}:
            raise ValueError(f"Invalid trigger_source: {v}")
        return v

    @model_validator(mode="after")
    def _check_delegation_id(self) -> ExecutionContract:
        if not ULID_RE.match(self.delegation_id):
            raise ValueError("delegation_id must be a valid ULID (26-char Crockford base32)")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self


def load_contract(path: Path | str) -> ExecutionContract:
    """Load and validate an execution contract from YAML."""
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return ExecutionContract.model_validate(data)
