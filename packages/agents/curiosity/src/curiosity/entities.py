"""Knowledge-graph entity model for D.12 hypothesis claims.

Per plan §Task 8, D.12 ships one entity model:

- ``HypothesisEntity`` — ``entity_type="hypothesis"``; one entity
  per hypothesis emitted. External_id is
  ``<customer_id>:<run_id>:<hypothesis_idx>``.

Unlike D.13 (which emits ONE ``SynthesisReportEntity`` per run),
D.12 emits N entities — one per hypothesis. This is the persistent
record that future A.4 Meta-Harness aggregation will scan over.

**Q6 invariant.** The persisted text has already passed Stage 4
REVIEW so it is guaranteed free of classifier-shaped substrings.
The entity model itself does no Q6 validation — that's the
reviewer's job.

**Single-tenant** per Q5. The KG writer (this module's sibling)
guards cross-tenant writes at the writer boundary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from ulid import ULID

from curiosity.schemas import UlidStr


class HypothesisEntity(BaseModel):
    """One hypothesis published in a run.

    The KG materialisation of a ``CuriosityClaim``. Both share the
    ``claim_id`` for cross-reference (the F.7 ``claims.>`` envelope
    carries the same claim_id; downstream consumers can join on it).
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    hypothesis_idx: int = Field(ge=0)
    claim_id: UlidStr
    statement: str = Field(min_length=1, max_length=400)
    target_agent: str = Field(min_length=1, max_length=64)
    cited_region: str = Field(min_length=1, max_length=64)
    emitted_at: datetime

    @field_validator("claim_id")
    @classmethod
    def _claim_id_is_ulid(cls, value: str) -> str:
        try:
            ULID.from_str(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"claim_id is not a valid ULID: {exc}") from exc
        return value

    @property
    def external_id(self) -> str:
        return f"{self.customer_id}:{self.run_id}:{self.hypothesis_idx}"

    def properties(self) -> dict[str, Any]:
        """Serialise to the SemanticStore properties dict."""
        return {
            "customer_id": self.customer_id,
            "run_id": self.run_id,
            "hypothesis_idx": self.hypothesis_idx,
            "claim_id": self.claim_id,
            "statement": self.statement,
            "target_agent": self.target_agent,
            "cited_region": self.cited_region,
            "emitted_at": self.emitted_at.isoformat(),
        }


__all__ = ["HypothesisEntity"]
