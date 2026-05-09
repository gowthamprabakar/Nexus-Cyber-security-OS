"""LLM provider interface — tier-based abstraction over reasoning models.

Per ADR-003. Every agent talks to LLMs through `LLMProvider`. The contract
specifies a `tier` (frontier / workhorse / edge); the deployment's
`provider_map` resolves tier → concrete `LLMProvider` at invocation time.
This module ships:

- The `LLMProvider` Protocol (`@runtime_checkable`).
- The shared types: `ModelTier`, `TokenUsage`, `ToolCall`, `ToolSchema`,
  `LLMResponse`.
- `FakeLLMProvider` — test double with canned responses.

Concrete providers (Anthropic, vLLM, Ollama, …) live in their own modules
so this file has no vendor SDK imports. See `charter.llm_anthropic` for
the first concrete implementation.

**Budget enforcement is the caller's responsibility.** A provider's
`complete()` returns the `LLMResponse` (with token counts) and emits an
audit entry pair when called inside an active `Charter` context. The
caller (typically an agent driver) is expected to charge the charter's
budget envelope based on `LLMResponse.usage`.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class ModelTier(StrEnum):
    """The three tiers a contract may request.

    Resolution to a concrete provider happens at invocation time per the
    deployment's provider_map (per ADR-003).
    """

    FRONTIER = "frontier"
    WORKHORSE = "workhorse"
    EDGE = "edge"


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token accounting from a single LLM call."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A single tool call requested by the model in its response."""

    name: str
    input: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolSchema:
    """Schema for a tool the model is permitted to call.

    The shape mirrors the OpenAI-/Anthropic-compatible JSON Schema layout.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    allowed_tier: ModelTier | None = None


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Result of one `LLMProvider.complete()` call."""

    text: str
    stop_reason: str
    usage: TokenUsage
    tool_calls: tuple[ToolCall, ...] = ()
    model_pin: str = ""
    provider_id: str = ""


@runtime_checkable
class LLMProvider(Protocol):
    """Vendor-neutral async interface every agent uses to talk to LLMs.

    A provider implementation MUST:
    - be `async`-callable on `complete(...)`;
    - require a non-empty `model_pin` (audit needs the exact model ID);
    - emit `llm_call_started` and `llm_call_completed` audit entries when
      called inside an active `Charter` context (detected via
      `charter.current_charter()`); no emission outside a Charter.

    Budget enforcement is the caller's responsibility (see module docstring).
    """

    @property
    def provider_id(self) -> str:
        """Stable provider identifier, e.g. "anthropic", "vllm", "ollama"."""

    @property
    def model_class(self) -> ModelTier:
        """The tier this provider serves under the deployment's provider_map."""

    async def complete(
        self,
        *,
        prompt: str,
        model_pin: str,
        max_tokens: int,
        system: str | None = None,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        tools: list[ToolSchema] | None = None,
    ) -> LLMResponse: ...


class FakeLLMProvider:
    """Deterministic test double — returns canned `LLMResponse`s in order.

    Construct with one or more responses; consecutive `complete()` calls
    return them in order, raising `StopIteration` if exhausted.
    """

    def __init__(
        self,
        responses: Iterable[LLMResponse],
        *,
        provider_id: str = "fake",
        model_class: ModelTier = ModelTier.WORKHORSE,
    ) -> None:
        self._responses: Iterator[LLMResponse] = iter(list(responses))
        self._provider_id = provider_id
        self._model_class = model_class
        self.calls: list[dict[str, Any]] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def model_class(self) -> ModelTier:
        return self._model_class

    async def complete(
        self,
        *,
        prompt: str,
        model_pin: str,
        max_tokens: int,
        system: str | None = None,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        tools: list[ToolSchema] | None = None,
    ) -> LLMResponse:
        if not model_pin:
            raise ValueError("model_pin must be non-empty")
        self.calls.append(
            {
                "prompt": prompt,
                "model_pin": model_pin,
                "max_tokens": max_tokens,
                "system": system,
                "temperature": temperature,
                "stop": stop,
                "tools": tools,
            }
        )
        return next(self._responses)
