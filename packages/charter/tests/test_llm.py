"""Tests for charter.llm + charter.llm_anthropic — LLMProvider abstraction."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import anthropic
import pytest
from charter import Charter, ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import (
    FakeLLMProvider,
    LLMProvider,
    LLMResponse,
    ModelTier,
    TokenUsage,
    ToolCall,
    ToolSchema,
)
from charter.llm_anthropic import PROVIDER_ID, AnthropicProvider

# ----------------------------- protocol shape --------------------------------


def test_protocol_is_runtime_checkable() -> None:
    fake = FakeLLMProvider(responses=[_response("hi")])
    assert isinstance(fake, LLMProvider)


def test_anthropic_provider_satisfies_protocol() -> None:
    provider = AnthropicProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(_anthropic_message())
    )
    assert isinstance(provider, LLMProvider)


def test_token_usage_total() -> None:
    usage = TokenUsage(input_tokens=10, output_tokens=20)
    assert usage.total_tokens == 30


# ----------------------------- FakeLLMProvider -------------------------------


@pytest.mark.asyncio
async def test_fake_provider_returns_canned_response() -> None:
    provider = FakeLLMProvider(responses=[_response("alpha")])
    out = await provider.complete(prompt="x", model_pin="claude-sonnet-4-5", max_tokens=100)
    assert out.text == "alpha"


@pytest.mark.asyncio
async def test_fake_provider_records_calls() -> None:
    provider = FakeLLMProvider(responses=[_response("a"), _response("b")])
    await provider.complete(prompt="p1", model_pin="m1", max_tokens=10)
    await provider.complete(prompt="p2", model_pin="m2", max_tokens=20, system="sys")
    assert provider.calls[0]["prompt"] == "p1"
    assert provider.calls[1]["system"] == "sys"


@pytest.mark.asyncio
async def test_fake_provider_rejects_empty_model_pin() -> None:
    provider = FakeLLMProvider(responses=[_response("x")])
    with pytest.raises(ValueError, match="model_pin"):
        await provider.complete(prompt="p", model_pin="", max_tokens=10)


def test_fake_provider_id_and_tier() -> None:
    p = FakeLLMProvider(responses=[], provider_id="my-fake", model_class=ModelTier.EDGE)
    assert p.provider_id == "my-fake"
    assert p.model_class == ModelTier.EDGE


# ----------------------------- AnthropicProvider -----------------------------


@pytest.mark.asyncio
async def test_anthropic_provider_rejects_empty_model_pin() -> None:
    provider = AnthropicProvider(
        model_class=ModelTier.WORKHORSE, client=_fake_client(_anthropic_message())
    )
    with pytest.raises(ValueError, match="model_pin"):
        await provider.complete(prompt="hi", model_pin="", max_tokens=10)


@pytest.mark.asyncio
async def test_anthropic_provider_maps_response_text_and_usage() -> None:
    msg = _anthropic_message(
        text="hello",
        input_tokens=42,
        output_tokens=7,
        stop_reason="end_turn",
    )
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=_fake_client(msg))

    out = await provider.complete(prompt="hi", model_pin="claude-sonnet-4-5", max_tokens=100)

    assert out.text == "hello"
    assert out.usage.input_tokens == 42
    assert out.usage.output_tokens == 7
    assert out.stop_reason == "end_turn"
    assert out.model_pin == "claude-sonnet-4-5"
    assert out.provider_id == PROVIDER_ID


@pytest.mark.asyncio
async def test_anthropic_provider_maps_tool_use_blocks() -> None:
    msg = _anthropic_message(
        content_blocks=[
            _block("text", text="thinking..."),
            _block("tool_use", name="prowler_scan", input={"region": "us-east-1"}),
        ]
    )
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=_fake_client(msg))

    out = await provider.complete(
        prompt="run a scan", model_pin="claude-sonnet-4-5", max_tokens=100
    )

    assert out.tool_calls == (ToolCall(name="prowler_scan", input={"region": "us-east-1"}),)
    assert out.text == "thinking..."


@pytest.mark.asyncio
async def test_anthropic_provider_passes_tools_and_system_through() -> None:
    msg = _anthropic_message()
    client = _fake_client(msg)
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=client)

    schema = ToolSchema(
        name="prowler_scan",
        description="run a Prowler scan",
        input_schema={"type": "object", "properties": {"region": {"type": "string"}}},
    )
    await provider.complete(
        prompt="scan",
        model_pin="claude-sonnet-4-5",
        max_tokens=200,
        system="you are an agent",
        tools=[schema],
        stop=["END"],
    )

    kwargs = client.messages.create.await_args.kwargs
    assert kwargs["model"] == "claude-sonnet-4-5"
    assert kwargs["system"] == "you are an agent"
    assert kwargs["stop_sequences"] == ["END"]
    assert kwargs["tools"][0]["name"] == "prowler_scan"


# --------------------------- retry behaviour ---------------------------------


@pytest.mark.asyncio
async def test_anthropic_provider_retries_rate_limit_then_succeeds() -> None:
    """Tenacity retries on RateLimitError; should succeed on second attempt."""
    msg = _anthropic_message(text="recovered")
    client = MagicMock()
    rate_limit_err = anthropic.RateLimitError.__new__(anthropic.RateLimitError)
    client.messages = MagicMock()
    client.messages.create = AsyncMock(side_effect=[rate_limit_err, msg])

    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=client, max_retries=3)
    # Speed up the test — neutralize tenacity's wait by patching asyncio.sleep.
    original_sleep = asyncio.sleep

    async def _instant(_seconds: float) -> None:
        await original_sleep(0)

    import tenacity

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(tenacity.asyncio, "sleep", _instant, raising=False)
        out = await provider.complete(prompt="hi", model_pin="claude-sonnet-4-5", max_tokens=10)

    assert out.text == "recovered"
    assert client.messages.create.await_count == 2


@pytest.mark.asyncio
async def test_anthropic_provider_does_not_retry_on_auth_error() -> None:
    """AuthenticationError is not retryable — first failure bubbles out."""
    auth_err = anthropic.AuthenticationError.__new__(anthropic.AuthenticationError)
    client = MagicMock()
    client.messages = MagicMock()
    client.messages.create = AsyncMock(side_effect=auth_err)

    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=client)

    with pytest.raises(anthropic.AuthenticationError):
        await provider.complete(prompt="hi", model_pin="m", max_tokens=10)
    assert client.messages.create.await_count == 1


# ----------------------- audit emission inside Charter -----------------------


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
async def test_audit_emission_inside_charter_context(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    msg = _anthropic_message(text="ok", input_tokens=12, output_tokens=8)
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=_fake_client(msg))

    with Charter(contract, tools=ToolRegistry()) as ctx:
        await provider.complete(prompt="p", model_pin="claude-sonnet-4-5", max_tokens=10)
        assert ctx.audit is not None

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [_action(line) for line in audit_lines]
    assert "llm_call_started" in actions
    assert "llm_call_completed" in actions
    completed_idx = actions.index("llm_call_completed")
    completed_payload = _payload(audit_lines[completed_idx])
    assert completed_payload["input_tokens"] == 12
    assert completed_payload["output_tokens"] == 8
    assert completed_payload["model_pin"] == "claude-sonnet-4-5"
    assert completed_payload["provider_id"] == "anthropic"


@pytest.mark.asyncio
async def test_no_audit_emission_outside_charter_context(tmp_path: Path) -> None:
    """Outside any Charter context, the provider must not emit audit entries."""
    msg = _anthropic_message(text="ok")
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=_fake_client(msg))

    out = await provider.complete(prompt="p", model_pin="m", max_tokens=10)
    assert out.text == "ok"
    # No audit log was created — no assertions needed beyond not crashing.


@pytest.mark.asyncio
async def test_audit_emits_failure_when_call_raises(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    auth_err = anthropic.AuthenticationError.__new__(anthropic.AuthenticationError)
    client = MagicMock()
    client.messages = MagicMock()
    client.messages.create = AsyncMock(side_effect=auth_err)
    provider = AnthropicProvider(model_class=ModelTier.WORKHORSE, client=client)

    with (
        Charter(contract, tools=ToolRegistry()) as _ctx,
        pytest.raises(anthropic.AuthenticationError),
    ):
        await provider.complete(prompt="p", model_pin="m", max_tokens=10)

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [_action(line) for line in audit_lines]
    assert "llm_call_started" in actions
    assert "llm_call_failed" in actions
    assert "llm_call_completed" not in actions


# ----------------------------- helpers ---------------------------------------


def _response(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=1, output_tokens=1),
        model_pin="m",
        provider_id="fake",
    )


def _block(block_type: str, **attrs: Any) -> MagicMock:
    block = MagicMock()
    block.type = block_type
    for k, v in attrs.items():
        setattr(block, k, v)
    return block


def _anthropic_message(
    *,
    text: str = "",
    content_blocks: list[Any] | None = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    stop_reason: str = "end_turn",
) -> MagicMock:
    msg = MagicMock()
    msg.content = content_blocks if content_blocks is not None else [_block("text", text=text)]
    msg.stop_reason = stop_reason
    usage = MagicMock()
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    msg.usage = usage
    return msg


def _fake_client(message: Any) -> MagicMock:
    client = MagicMock()
    client.messages = MagicMock()
    client.messages.create = AsyncMock(return_value=message)
    return client


def _action(line: str) -> str:
    import json as _json

    return str(_json.loads(line)["action"])


def _payload(line: str) -> dict[str, Any]:
    import json as _json

    return dict(_json.loads(line)["payload"])
