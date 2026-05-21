"""Knowledge-graph entity models for A.4 Meta-Harness run output.

Per Q1 of the A.4 plan, A.4 emits two entity types per run:

- ``AgentScorecard`` — ``entity_type="agent_scorecard"``; one per
  evaluated agent per A.4 run. External_id:
  ``<customer_id>:<run_id>:<evaluated_agent_id>``.
- ``ABComparisonResult`` — ``entity_type="ab_comparison_result"``;
  one per A/B run (only when the ``ab-compare`` subcommand is used).
  External_id: ``<customer_id>:<run_id>:<agent_id>:<variant_a>:<variant_b>``.

**Read-only persistence shape.** These models are the KG-side
materialization of the runtime Scorecard / ABComparison pydantic
types from ``meta_harness.schemas``. They re-encode the data into a
properties dict suitable for SemanticStore upsert.

**Single-tenant** per Q5. The KG writer (this module's sibling)
guards cross-tenant writes at the writer boundary.

**Q-ARCH-2 reminder.** Persistence is to SemanticStore only; no
bus subject emission. v0.2 may introduce a meta/proposals fabric
subject for real-time consumers (deferral named in the plan doc).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_AGENT_ID_LENGTH = 64
_MAX_PATH_LENGTH = 512
_MIN_PASS_RATE = 0.0
_MAX_PASS_RATE = 1.0


class AgentScorecard(BaseModel):
    """KG materialization of one ``Scorecard`` from a Meta-Harness run.

    The persistent record future A.4 runs read via the kg_query
    helper (Task 10's driver) to populate ``previous_pass_rate`` on
    each ScorecardDelta. The composite key
    ``(tenant_id="<customer>", entity_type="agent_scorecard",
    external_id="<customer>:<run_id>:<agent_id>")`` makes each
    Meta-Harness run + per-agent row idempotent.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    total_cases: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    pass_rate: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    error: str | None = Field(default=None, max_length=512)
    evaluated_at: datetime

    @model_validator(mode="after")
    def _xor_passrate_error(self) -> AgentScorecard:
        if self.pass_rate is None and self.error is None:
            raise ValueError(
                "AgentScorecard requires either pass_rate (success) or error (failure)"
            )
        if self.pass_rate is not None and self.error is not None:
            raise ValueError("AgentScorecard cannot carry both pass_rate and error — they are XOR")
        return self

    @property
    def external_id(self) -> str:
        return f"{self.customer_id}:{self.run_id}:{self.agent_id}"

    def properties(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "total_cases": self.total_cases,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": self.pass_rate,
            "error": self.error,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class ABComparisonResult(BaseModel):
    """KG materialization of an ``ABComparison`` (when A/B run).

    External_id encodes both variant paths so concurrent A/B runs
    against different variant pairs don't collide.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    variant_a_path: str = Field(min_length=1, max_length=_MAX_PATH_LENGTH)
    variant_b_path: str = Field(min_length=1, max_length=_MAX_PATH_LENGTH)
    variant_a_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    variant_b_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    byte_equal: bool
    evaluated_at: datetime

    @model_validator(mode="after")
    def _variants_differ(self) -> ABComparisonResult:
        if self.variant_a_path == self.variant_b_path:
            raise ValueError(
                "variant_a_path and variant_b_path must differ — A/B compares two variants"
            )
        return self

    @property
    def external_id(self) -> str:
        return (
            f"{self.customer_id}:{self.run_id}:{self.agent_id}:"
            f"{self.variant_a_path}:{self.variant_b_path}"
        )

    def properties(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "variant_a_path": self.variant_a_path,
            "variant_b_path": self.variant_b_path,
            "variant_a_pass_rate": self.variant_a_pass_rate,
            "variant_b_pass_rate": self.variant_b_pass_rate,
            "byte_equal": self.byte_equal,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


__all__ = ["ABComparisonResult", "AgentScorecard"]
