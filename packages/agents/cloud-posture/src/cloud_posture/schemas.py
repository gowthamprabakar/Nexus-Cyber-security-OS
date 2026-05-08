"""Cloud Posture finding and report schemas."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

FINDING_ID_RE = re.compile(r"^CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AffectedResource(BaseModel):
    cloud: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    region: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    arn: str = Field(min_length=1)


class Finding(BaseModel):
    finding_id: str
    rule_id: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    affected: list[AffectedResource] = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime
    suppressed: bool = False
    suppression_reason: str | None = None

    @field_validator("finding_id")
    @classmethod
    def _check_format(cls, v: str) -> str:
        if not FINDING_ID_RE.match(v):
            raise ValueError(
                f"finding_id must match CSPM-<CLOUD>-<SVC>-<NNN>-<context> (got {v!r})"
            )
        return v


class FindingsReport(BaseModel):
    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    scan_started_at: datetime
    scan_completed_at: datetime
    findings: list[Finding]

    @property
    def total(self) -> int:
        return len(self.findings)

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
