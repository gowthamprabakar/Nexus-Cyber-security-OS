"""OpenAICompatibleProvider — works against any OpenAI-compatible HTTP endpoint.

Per ADR-006: a single provider class covers most non-Anthropic LLM sources
because vLLM, Ollama, OpenAI, OpenRouter, Together, Fireworks, Groq, DeepSeek,
llama.cpp server, and LM Studio all expose the OpenAI Chat Completions API.
Configure with `base_url` + `api_key` to target any of them.

Convenience constructors:
- `OpenAICompatibleProvider.for_vllm_local(...)` — `http://localhost:8000/v1`
- `OpenAICompatibleProvider.for_ollama(...)` — `http://localhost:11434/v1`

Optional extra: install with `pip install nexus-charter[openai-compatible]`.
"""

from __future__ import annotations

import json
from typing import Any

import openai
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

DEFAULT_PROVIDER_ID = "openai-compatible"

# Errors worth retrying: transient capacity / network / rate-limit issues.
# Auth / permission / bad-request / not-found are caller bugs and bubble up.
_RETRYABLE = (
    openai.RateLimitError,
    openai.InternalServerError,
    openai.APIConnectionError,
    openai.APITimeoutError,
)


class OpenAICompatibleProvider:
    """`LLMProvider` for any OpenAI-compatible HTTP endpoint.

    Set `base_url` to target a non-OpenAI service. Set `provider_id` to
    label audit entries clearly (e.g. `"vllm-local"`, `"openrouter"`).
    `model_class` is set at construction time and SHOULD match the
    contract's `tier` resolution.
    """

    def __init__(
        self,
        *,
        model_class: ModelTier,
        client: Any | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        provider_id: str = DEFAULT_PROVIDER_ID,
        max_retries: int = 5,
    ) -> None:
        self._client: Any = client or openai.AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self._model_class = model_class
        self._provider_id = provider_id
        self._max_retries = max_retries

    @classmethod
    def for_vllm_local(
        cls,
        *,
        model_class: ModelTier = ModelTier.WORKHORSE,
        base_url: str = "http://localhost:8000/v1",
        max_retries: int = 5,
    ) -> OpenAICompatibleProvider:
        """Convenience constructor for a local vLLM server.

        vLLM's OpenAI-compatible endpoint ignores `api_key` but the SDK
        requires a non-empty value, so we pass a placeholder.
        """
        return cls(
            model_class=model_class,
            api_key="EMPTY",
            base_url=base_url,
            provider_id="vllm-local",
            max_retries=max_retries,
        )

    @classmethod
    def for_ollama(
        cls,
        *,
        model_class: ModelTier = ModelTier.EDGE,
        base_url: str = "http://localhost:11434/v1",
        max_retries: int = 5,
    ) -> OpenAICompatibleProvider:
        """Convenience constructor for Ollama's OpenAI-compatible endpoint.

        Ollama serves at `:11434/v1` and ignores the api_key, but the SDK
        requires a non-empty value. Edge tier by default — Ollama is the
        common dev / air-gap path.
        """
        return cls(
            model_class=model_class,
            api_key="ollama",
            base_url=base_url,
            provider_id="ollama",
            max_retries=max_retries,
        )

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

        charter = current_charter()
        started_payload: dict[str, Any] = {
            "provider_id": self._provider_id,
            "model_pin": model_pin,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "tools": [t.name for t in tools] if tools else [],
        }
        if charter is not None and charter.audit is not None:
            charter.audit.append(action="llm_call_started", payload=started_payload)

        try:
            response = await self._call_with_retry(
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

        llm_response = _build_response(response, model_pin=model_pin, provider_id=self._provider_id)

        if charter is not None and charter.audit is not None:
            charter.audit.append(
                action="llm_call_completed",
                payload={
                    "provider_id": self._provider_id,
                    "model_pin": model_pin,
                    "input_tokens": llm_response.usage.input_tokens,
                    "output_tokens": llm_response.usage.output_tokens,
                    "stop_reason": llm_response.stop_reason,
                    "tool_calls": [tc.name for tc in llm_response.tool_calls],
                },
            )
        return llm_response

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
            messages: list[dict[str, Any]] = []
            if system is not None:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            kwargs: dict[str, Any] = {
                "model": model_pin,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if stop:
                kwargs["stop"] = stop
            if tools:
                kwargs["tools"] = [_tool_schema_to_openai(t) for t in tools]
            return await self._client.chat.completions.create(**kwargs)

        return await _go()


def _tool_schema_to_openai(schema: ToolSchema) -> dict[str, Any]:
    """OpenAI uses `{type: 'function', function: {name, description, parameters}}`."""
    return {
        "type": "function",
        "function": {
            "name": schema.name,
            "description": schema.description,
            "parameters": schema.input_schema,
        },
    }


def _build_response(response: Any, *, model_pin: str, provider_id: str) -> LLMResponse:
    """Map an OpenAI ChatCompletion response to our `LLMResponse`."""
    choice = response.choices[0]
    message = choice.message

    text = message.content or ""

    tool_calls: list[ToolCall] = []
    raw_tool_calls = getattr(message, "tool_calls", None) or []
    for tc in raw_tool_calls:
        if getattr(tc, "type", "function") != "function":
            continue
        func = tc.function
        try:
            arguments = json.loads(func.arguments) if func.arguments else {}
        except json.JSONDecodeError:
            # Tolerate models that emit malformed JSON arguments. Pass the
            # raw string up so the caller can surface a parsing error in
            # context rather than crashing the whole response build.
            arguments = {"_raw": func.arguments}
        tool_calls.append(ToolCall(name=func.name, input=arguments))

    usage_obj = getattr(response, "usage", None)
    usage = TokenUsage(
        input_tokens=int(getattr(usage_obj, "prompt_tokens", 0) or 0),
        output_tokens=int(getattr(usage_obj, "completion_tokens", 0) or 0),
    )

    return LLMResponse(
        text=text,
        stop_reason=str(getattr(choice, "finish_reason", "")),
        usage=usage,
        tool_calls=tuple(tool_calls),
        model_pin=model_pin,
        provider_id=provider_id,
    )
