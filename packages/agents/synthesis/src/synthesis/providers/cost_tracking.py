"""LLM call cost tracking (synthesis v0.2 Task 10, Q5/WI-Y11).

Records per-run LLM telemetry — call count, estimated tokens, and which provider answered
(DeepSeek vs the Anthropic fallback) — and emits it to the F.6 audit chain under the additive
``synthesis.llm.call_completed`` vocabulary entry. This is the cost signal Q5's v0.3
multi-provider optimization will consume. The action string is synthesis-local + additive (no
existing schema changed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter.audit import AuditLog
from charter.llm import LLMResponse

#: Additive F.6 audit vocabulary entry for an LLM call (WI-Y11).
ACTION_LLM_CALL_COMPLETED = "synthesis.llm.call_completed"


@dataclass(slots=True)
class LLMCostTracker:
    call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    provider_used: str | None = None

    def record(self, response: LLMResponse, *, provider_used: str) -> None:
        """Accumulate one LLM call's usage + the provider that answered it."""
        self.call_count += 1
        self.input_tokens += response.usage.input_tokens
        self.output_tokens += response.usage.output_tokens
        self.provider_used = provider_used

    @property
    def estimated_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_audit_payload(self) -> dict[str, Any]:
        return {
            "llm_call_count": self.call_count,
            "estimated_tokens": self.estimated_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "provider_used": self.provider_used,
        }


def emit_llm_cost(audit_log: AuditLog, *, tracker: LLMCostTracker) -> None:
    """Append the run's LLM cost telemetry to the F.6 audit chain (WI-Y11)."""
    audit_log.append(ACTION_LLM_CALL_COMPLETED, tracker.to_audit_payload())
