"""AnthropicProvider — concrete `LLMProvider` for the Anthropic Claude API.

Wraps `anthropic.AsyncAnthropic.messages.create(...)`, retries on rate-limit
and 5xx with exponential backoff, enforces a non-empty `model_pin`, and
emits `llm_call_started` / `llm_call_completed` (or `llm_call_failed`)
audit entries when called inside an active `Charter` context.

Optional extra: install with `pip install nexus-charter[anthropic]`. The
`anthropic` and `tenacity` packages are imported at module load; users
without the extra get an `ImportError` here, which is the intended signal.
"""

from __future__ import annotations

from typing import Any

import anthropic
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from charter.context import current_charter
from charter.llm import (
    LLMResponse,
    ModelTier,
    TokenUsage,
    ToolCall,
    ToolSchema,
)

PROVIDER_ID = "anthropic"

# Errors worth retrying: transient capacity / network / rate-limit issues.
# Auth / permission / bad-request / not-found are caller bugs and bubble up.
_RETRYABLE = (
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
)


class AnthropicProvider:
    """`LLMProvider` for the Anthropic Claude API.

    Construction is cheap; the underlying `AsyncAnthropic` client may be
    injected for tests. `model_class` is set at construction time and
    SHOULD match the contract's `tier` resolution.
    """

    def __init__(
        self,
        *,
        model_class: ModelTier,
        client: Any | None = None,
        api_key: str | None = None,
        max_retries: int = 5,
    ) -> None:
        self._client: Any = client or anthropic.AsyncAnthropic(api_key=api_key)
        self._model_class = model_class
        self._max_retries = max_retries

    @property
    def provider_id(self) -> str:
        return PROVIDER_ID

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

        charter = current_charter()
        started_payload: dict[str, Any] = {
            "provider_id": PROVIDER_ID,
            "model_pin": model_pin,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "tools": [t.name for t in tools] if tools else [],
        }
        if charter is not None and charter.audit is not None:
            charter.audit.append(action="llm_call_started", payload=started_payload)

        try:
            message = await self._call_with_retry(
                prompt=prompt,
                model_pin=model_pin,
                max_tokens=max_tokens,
                system=system,
                temperature=temperature,
                stop=stop,
                tools=tools,
            )
        except Exception as e:
            if charter is not None and charter.audit is not None:
                charter.audit.append(
                    action="llm_call_failed",
                    payload={
                        **started_payload,
                        "error_type": e.__class__.__name__,
                        "error": str(e),
                    },
                )
            raise

        response = _build_response(message, model_pin=model_pin)

        if charter is not None and charter.audit is not None:
            charter.audit.append(
                action="llm_call_completed",
                payload={
                    "provider_id": PROVIDER_ID,
                    "model_pin": model_pin,
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                    "stop_reason": response.stop_reason,
                    "tool_calls": [tc.name for tc in response.tool_calls],
                },
            )
        return response

    async def _call_with_retry(
        self,
        *,
        prompt: str,
        model_pin: str,
        max_tokens: int,
        system: str | None,
        temperature: float,
        stop: list[str] | None,
        tools: list[ToolSchema] | None,
    ) -> Any:
        @retry(
            retry=retry_if_exception_type(_RETRYABLE),
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=30),
            reraise=True,
        )
        async def _go() -> Any:
            kwargs: dict[str, Any] = {
                "model": model_pin,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            if system is not None:
                kwargs["system"] = system
            if stop:
                kwargs["stop_sequences"] = stop
            if tools:
                kwargs["tools"] = [_tool_schema_to_anthropic(t) for t in tools]
            return await self._client.messages.create(**kwargs)

        return await _go()


def _tool_schema_to_anthropic(schema: ToolSchema) -> dict[str, Any]:
    return {
        "name": schema.name,
        "description": schema.description,
        "input_schema": schema.input_schema,
    }


def _build_response(message: Any, *, model_pin: str) -> LLMResponse:
    """Map an Anthropic `Message` to our `LLMResponse`."""
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in getattr(message, "content", []) or []:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(getattr(block, "text", ""))
        elif block_type == "tool_use":
            tool_calls.append(
                ToolCall(
                    name=getattr(block, "name", ""),
                    input=dict(getattr(block, "input", {}) or {}),
                )
            )

    usage_obj = getattr(message, "usage", None)
    usage = TokenUsage(
        input_tokens=int(getattr(usage_obj, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage_obj, "output_tokens", 0) or 0),
    )

    return LLMResponse(
        text="".join(text_parts),
        stop_reason=str(getattr(message, "stop_reason", "")),
        usage=usage,
        tool_calls=tuple(tool_calls),
        model_pin=model_pin,
        provider_id=PROVIDER_ID,
    )
