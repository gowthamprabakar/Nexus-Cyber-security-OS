"""Knowledge-graph entity model for D.13 synthesis reports.

Per plan §Task 8, D.13 ships one entity model:

- ``SynthesisReportEntity`` — ``entity_type="synthesis_report"``;
  one per agent run. External_id is ``<customer_id>:<run_id>``.
  Properties carry section count + executive-summary paragraph +
  cited-finding count + scan-window metadata + review retry count.

**The full narrative.md stays in the workspace.** Per the plan, only
the C-suite digest (executive_summary paragraph) is persisted to the
SemanticStore — the full per-section markdown lives in the charter
workspace as ``narrative.md``. This keeps the KG entity sized for
fast cross-run lookups (downstream consumers like A.4 Meta-Harness
read this entity to count synthesis activity per customer per window).

Q6 invariant: the executive_summary paragraph has already passed
through Stage 4 REVIEW (Task 7) before reaching this entity, so the
persisted text is guaranteed free of classifier-shaped substrings.
The entity model itself does no Q6 validation — that's the reviewer's
job.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SynthesisReportEntity(BaseModel):
    """One D.13 synthesis run (``entity_type="synthesis_report"``).

    The external_id is ``<customer_id>:<run_id>``; this keeps the
    KG entity's namespace per-customer-per-run so cross-window
    lookups are straightforward and re-runs of the same run_id
    overwrite cleanly via the upsert key.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    section_count: int = Field(ge=0)
    executive_summary_paragraph: str = Field(min_length=1, max_length=2000)
    total_cited_findings: int = Field(ge=0)
    scan_started_at: datetime
    scan_completed_at: datetime
    review_retries: int = Field(default=0, ge=0)

    @property
    def external_id(self) -> str:
        return f"{self.customer_id}:{self.run_id}"

    def properties(self) -> dict[str, Any]:
        """Serialise to the SemanticStore properties dict."""
        return {
            "customer_id": self.customer_id,
            "run_id": self.run_id,
            "section_count": self.section_count,
            "executive_summary_paragraph": self.executive_summary_paragraph,
            "total_cited_findings": self.total_cited_findings,
            "scan_started_at": self.scan_started_at.isoformat(),
            "scan_completed_at": self.scan_completed_at.isoformat(),
            "review_retries": self.review_retries,
        }


__all__ = ["SynthesisReportEntity"]
