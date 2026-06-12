"""LLM call cost tracking per investigation (investigation v0.2 Task 6, Q3/WI-I17).

Inherits the D.13 pattern: records per-investigation LLM telemetry — total calls, estimated
tokens, and which provider answered (DeepSeek vs the Anthropic fallback) — and emits it to the
F.6 audit chain under the additive ``investigation.llm.call_completed`` vocabulary entry. The
action string is investigation-local + additive (no existing schema changed). A cost section is
attached to the IncidentReport (Task 13).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter.audit import AuditLog
from charter.llm import LLMResponse

#: Additive F.6 audit vocabulary entry for an LLM call (WI-I17).
ACTION_LLM_CALL_COMPLETED = "investigation.llm.call_completed"


@dataclass(slots=True)
class InvestigationCostTracker:
    llm_call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    provider_used: str | None = None

    def record(self, response: LLMResponse, *, provider_used: str) -> None:
        """Accumulate one LLM call's usage + the provider that answered it."""
        self.llm_call_count += 1
        self.input_tokens += response.usage.input_tokens
        self.output_tokens += response.usage.output_tokens
        self.provider_used = provider_used

    @property
    def estimated_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_report_section(self) -> dict[str, Any]:
        """The cost-telemetry section attached to the IncidentReport (WI-I17)."""
        return {
            "llm_call_count": self.llm_call_count,
            "estimated_tokens": self.estimated_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "provider_used": self.provider_used,
        }


def emit_llm_cost(audit_log: AuditLog, *, tracker: InvestigationCostTracker) -> None:
    """Append the investigation's LLM cost telemetry to the F.6 audit chain (WI-I17)."""
    audit_log.append(ACTION_LLM_CALL_COMPLETED, tracker.to_report_section())
