"""LLM cost telemetry per scan window (curiosity v0.2 Task 11, Q3/H4).

Inherits the D.13/D.7 pattern: records per-scan LLM telemetry — total calls, estimated tokens,
and which provider answered (DeepSeek vs the Anthropic fallback) — and emits it to the F.6 audit
chain under the additive ``curiosity.llm.call_completed`` vocabulary entry (no existing schema
changed). **H4/WI-X15 nuance:** most scan windows DETECT no gaps and skip the LLM entirely; that
is the common, cheap path and is recorded as ``llm_skipped=True`` (zero calls) — the cost report
makes the skip explicit rather than implying a silent zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter.audit import AuditLog
from charter.llm import LLMResponse

#: Additive F.6 audit vocabulary entry for a curiosity scan's LLM cost.
ACTION_LLM_CALL_COMPLETED = "curiosity.llm.call_completed"


@dataclass(slots=True)
class CuriosityCostTracker:
    llm_call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    provider_used: str | None = None
    llm_skipped: bool = False

    def record(self, response: LLMResponse, *, provider_used: str) -> None:
        """Accumulate one LLM call's usage + the provider that answered it."""
        self.llm_call_count += 1
        self.input_tokens += response.usage.input_tokens
        self.output_tokens += response.usage.output_tokens
        self.provider_used = provider_used
        self.llm_skipped = False

    def record_skip(self) -> None:
        """H4: the scan window detected no gaps, so the LLM was skipped (the common path)."""
        self.llm_skipped = True

    @property
    def estimated_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_report_section(self) -> dict[str, Any]:
        """The cost-telemetry section for the scan."""
        return {
            "llm_call_count": self.llm_call_count,
            "estimated_tokens": self.estimated_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "provider_used": self.provider_used,
            "llm_skipped": self.llm_skipped,
        }


def emit_llm_cost(audit_log: AuditLog, *, tracker: CuriosityCostTracker) -> None:
    """Append the scan's LLM cost telemetry to the F.6 audit chain."""
    audit_log.append(ACTION_LLM_CALL_COMPLETED, tracker.to_report_section())
