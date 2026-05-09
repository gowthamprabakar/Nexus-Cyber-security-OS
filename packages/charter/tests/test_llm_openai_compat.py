"""Tests for charter.llm_openai_compat — OpenAI-compatible LLM provider.

The single `OpenAICompatibleProvider` class subsumes OpenAI proper, vLLM,
Ollama, OpenRouter, etc. (per ADR-006). Tests focus on the wire-format
mapping, audit emission, retry policy, and the convenience constructors.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import openai
import pytest
from charter import Charter, ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider, ModelTier, ToolCall, ToolSchema
from charter.llm_openai_compat import (
    DEFAULT_PROVIDER_ID,
    OpenAICompatibleProvider,
)

# --------------------------- protocol shape ---------------------------------


def test_protocol_satisfaction() -> None:
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(_openai_response())
    )
    assert isinstance(provider, LLMProvider)


def test_default_provider_id() -> None:
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(_openai_response())
    )
    assert provider.provider_id == DEFAULT_PROVIDER_ID
    assert provider.model_class == ModelTier.WORKHORSE


# --------------------------- input validation -------------------------------


@pytest.mark.asyncio
async def test_rejects_empty_model_pin() -> None:
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(_openai_response())
    )
    with pytest.raises(ValueError, match="model_pin"):
        await provider.complete(prompt="hi", model_pin="", max_tokens=10)


# --------------------------- response mapping -------------------------------


@pytest.mark.asyncio
async def test_maps_response_text_and_usage() -> None:
    response = _openai_response(
        text="hello",
        prompt_tokens=42,
        completion_tokens=7,
        finish_reason="stop",
    )
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(response)
    )

    out = await provider.complete(prompt="hi", model_pin="gpt-4o-mini", max_tokens=100)

    assert out.text == "hello"
    assert out.usage.input_tokens == 42
    assert out.usage.output_tokens == 7
    assert out.stop_reason == "stop"
    assert out.model_pin == "gpt-4o-mini"
    assert out.provider_id == DEFAULT_PROVIDER_ID


@pytest.mark.asyncio
async def test_maps_tool_calls_with_json_arguments() -> None:
    response = _openai_response(
        tool_calls=[
            _tool_call("prowler_scan", {"region": "us-east-1"}),
        ]
    )
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(response)
    )
    out = await provider.complete(prompt="scan", model_pin="gpt-4o", max_tokens=100)
    assert out.tool_calls == (ToolCall(name="prowler_scan", input={"region": "us-east-1"}),)


@pytest.mark.asyncio
async def test_maps_tool_call_with_malformed_json_arguments() -> None:
    """If a model emits non-JSON arguments, surface them as `_raw` rather than crashing."""
    response = _openai_response(tool_calls=[_tool_call("prowler_scan", arguments_str="not-json")])
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(response)
    )
    out = await provider.complete(prompt="scan", model_pin="gpt-4o", max_tokens=100)
    assert out.tool_calls[0].input == {"_raw": "not-json"}


# --------------------------- request shape ----------------------------------


@pytest.mark.asyncio
async def test_system_prompt_threaded_into_messages() -> None:
    response = _openai_response()
    client = _fake_client(response)
    provider = OpenAICompatibleProvider(model_class=ModelTier.WORKHORSE, client=client)
    await provider.complete(
        prompt="hi", model_pin="gpt-4o", max_tokens=10, system="you are an agent"
    )
    kwargs = client.chat.completions.create.await_args.kwargs
    assert kwargs["messages"] == [
        {"role": "system", "content": "you are an agent"},
        {"role": "user", "content": "hi"},
    ]


@pytest.mark.asyncio
async def test_tools_converted_to_openai_function_shape() -> None:
    response = _openai_response()
    client = _fake_client(response)
    provider = OpenAICompatibleProvider(model_class=ModelTier.WORKHORSE, client=client)
    schema = ToolSchema(
        name="prowler_scan",
        description="run a Prowler scan",
        input_schema={"type": "object", "properties": {"region": {"type": "string"}}},
    )
    await provider.complete(
        prompt="scan",
        model_pin="gpt-4o",
        max_tokens=200,
        tools=[schema],
        stop=["END"],
    )
    kwargs = client.chat.completions.create.await_args.kwargs
    assert kwargs["stop"] == ["END"]
    assert kwargs["tools"][0] == {
        "type": "function",
        "function": {
            "name": "prowler_scan",
            "description": "run a Prowler scan",
            "parameters": {
                "type": "object",
                "properties": {"region": {"type": "string"}},
            },
        },
    }


# --------------------------- retry policy -----------------------------------


@pytest.mark.asyncio
async def test_retries_rate_limit_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _openai_response(text="recovered")
    rate_limit_err = openai.RateLimitError.__new__(openai.RateLimitError)
    client = MagicMock()
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=[rate_limit_err, response])

    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=client, max_retries=3
    )

    import tenacity

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(tenacity.asyncio, "sleep", _instant, raising=False)
    out = await provider.complete(prompt="hi", model_pin="gpt-4o", max_tokens=10)

    assert out.text == "recovered"
    assert client.chat.completions.create.await_count == 2


@pytest.mark.asyncio
async def test_does_not_retry_on_auth_error() -> None:
    auth_err = openai.AuthenticationError.__new__(openai.AuthenticationError)
    client = MagicMock()
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=auth_err)
    provider = OpenAICompatibleProvider(model_class=ModelTier.WORKHORSE, client=client)

    with pytest.raises(openai.AuthenticationError):
        await provider.complete(prompt="hi", model_pin="gpt-4o", max_tokens=10)
    assert client.chat.completions.create.await_count == 1


# --------------------------- audit emission ---------------------------------


def _make_contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="t",
        required_outputs=["findings.json"],
        budget=BudgetSpec(
            llm_calls=10,
            tokens=10000,
            wall_clock_sec=60.0,
            cloud_api_calls=100,
            mb_written=10,
        ),
        permitted_tools=["echo"],
        completion_condition="done",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


@pytest.mark.asyncio
async def test_audit_emission_inside_charter(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    response = _openai_response(text="ok", prompt_tokens=12, completion_tokens=8)
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE,
        client=_fake_client(response),
        provider_id="vllm-local",
    )

    with Charter(contract, tools=ToolRegistry()):
        await provider.complete(
            prompt="p", model_pin="meta-llama/Llama-3.3-70B-Instruct", max_tokens=10
        )

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [_action(line) for line in audit_lines]
    assert "llm_call_started" in actions
    assert "llm_call_completed" in actions

    completed_idx = actions.index("llm_call_completed")
    completed_payload = _payload(audit_lines[completed_idx])
    assert completed_payload["provider_id"] == "vllm-local"
    assert completed_payload["model_pin"] == "meta-llama/Llama-3.3-70B-Instruct"
    assert completed_payload["input_tokens"] == 12
    assert completed_payload["output_tokens"] == 8


@pytest.mark.asyncio
async def test_no_audit_outside_charter() -> None:
    response = _openai_response(text="ok")
    provider = OpenAICompatibleProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(response)
    )
    out = await provider.complete(prompt="p", model_pin="gpt-4o", max_tokens=10)
    assert out.text == "ok"


@pytest.mark.asyncio
async def test_audit_emits_failure(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    auth_err = openai.AuthenticationError.__new__(openai.AuthenticationError)
    client = MagicMock()
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=auth_err)
    provider = OpenAICompatibleProvider(model_class=ModelTier.WORKHORSE, client=client)

    with Charter(contract, tools=ToolRegistry()), pytest.raises(openai.AuthenticationError):
        await provider.complete(prompt="p", model_pin="gpt-4o", max_tokens=10)

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [_action(line) for line in audit_lines]
    assert "llm_call_started" in actions
    assert "llm_call_failed" in actions
    assert "llm_call_completed" not in actions


# --------------------------- convenience constructors -----------------------


def test_for_vllm_local_defaults() -> None:
    provider = OpenAICompatibleProvider.for_vllm_local()
    assert provider.provider_id == "vllm-local"
    assert provider.model_class == ModelTier.WORKHORSE


def test_for_ollama_defaults() -> None:
    provider = OpenAICompatibleProvider.for_ollama()
    assert provider.provider_id == "ollama"
    assert provider.model_class == ModelTier.EDGE


def test_for_vllm_local_accepts_custom_base_url() -> None:
    provider = OpenAICompatibleProvider.for_vllm_local(
        base_url="http://gpu-host.internal:8080/v1",
        model_class=ModelTier.WORKHORSE,
    )
    assert provider.provider_id == "vllm-local"
    assert provider.model_class == ModelTier.WORKHORSE


# --------------------------- helpers ----------------------------------------


def _tool_call(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    arguments_str: str | None = None,
) -> MagicMock:
    tc = MagicMock()
    tc.type = "function"
    tc.function = MagicMock()
    tc.function.name = name
    if arguments_str is not None:
        tc.function.arguments = arguments_str
    else:
        tc.function.arguments = json.dumps(arguments or {})
    return tc


def _openai_response(
    *,
    text: str = "",
    tool_calls: list[Any] | None = None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    finish_reason: str = "stop",
) -> MagicMock:
    message = MagicMock()
    message.content = text
    message.tool_calls = tool_calls or []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason

    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens

    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


def _fake_client(response: Any) -> MagicMock:
    client = MagicMock()
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=response)
    return client


def _action(line: str) -> str:
    return str(json.loads(line)["action"])


def _payload(line: str) -> dict[str, Any]:
    return dict(json.loads(line)["payload"])
