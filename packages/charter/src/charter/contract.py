"""Execution contract — the signed YAML that defines an agent invocation."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, Field, StringConstraints, model_validator

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
