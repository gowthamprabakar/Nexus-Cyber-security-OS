"""Live integration tests against Ollama through `OpenAICompatibleProvider`.

Skipped by default. Enable with:

    NEXUS_LIVE_OLLAMA=1 uv run pytest \\
        packages/charter/tests/integration/test_llm_ollama_live.py -v

Prerequisites for the run:
- Ollama running at `http://localhost:11434` (override with NEXUS_OLLAMA_URL).
- The model named by `NEXUS_LIVE_OLLAMA_MODEL` (default `qwen3:4b`) is
  pulled (`ollama pull qwen3:4b`).

These tests exist to prove the LLMProvider abstraction round-trips against
a real model — the unit tests in `test_llm_openai_compat.py` only mock the
SDK and can't catch wire-format regressions.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from charter import Charter, ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMResponse
from charter.llm_openai_compat import OpenAICompatibleProvider

pytestmark = pytest.mark.integration


_OLLAMA_URL_BASE = os.environ.get("NEXUS_OLLAMA_URL", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL = os.environ.get("NEXUS_LIVE_OLLAMA_MODEL", "qwen3:4b")


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_OLLAMA") == "1"


def _ollama_available() -> bool:
    try:
        r = httpx.get(f"{_OLLAMA_URL_BASE}/api/tags", timeout=2.0)
        if r.status_code != 200:
            return False
        models = {m["name"] for m in r.json().get("models", [])}
        return _OLLAMA_MODEL in models
    except (httpx.HTTPError, OSError, ValueError):
        return False


_skip_reason = (
    f"set NEXUS_LIVE_OLLAMA=1 and pull {_OLLAMA_MODEL!r} via "
    f"`ollama pull {_OLLAMA_MODEL}` to enable; current Ollama URL: {_OLLAMA_URL_BASE}"
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _live_enabled(), reason=_skip_reason),
    pytest.mark.skipif(
        _live_enabled() and not _ollama_available(),
        reason=f"NEXUS_LIVE_OLLAMA=1 set but Ollama at {_OLLAMA_URL_BASE} "
        f"is unreachable or model {_OLLAMA_MODEL!r} is not pulled",
    ),
]


@pytest.mark.asyncio
async def test_ollama_round_trip_returns_text_and_usage() -> None:
    provider = OpenAICompatibleProvider.for_ollama(
        base_url=f"{_OLLAMA_URL_BASE}/v1",
    )

    # `/no_think` is Qwen-3's documented directive to skip chain-of-thought.
    # Other models ignore it as text. Without it, Qwen-3 burns the whole token
    # budget inside <think>...</think> tags before emitting visible output.
    response = await provider.complete(
        prompt=(
            "/no_think You are a security auditor. In ONE short sentence, "
            "describe the top risk of an S3 bucket with a public-read ACL."
        ),
        model_pin=_OLLAMA_MODEL,
        max_tokens=400,
        temperature=0.0,
    )

    assert isinstance(response, LLMResponse)
    assert response.text.strip(), (
        f"expected non-empty text from {_OLLAMA_MODEL}, got {response.text!r}"
    )
    assert response.usage.input_tokens > 0
    assert response.usage.output_tokens > 0
    assert response.provider_id == "ollama"
    assert response.model_pin == _OLLAMA_MODEL
    # `stop` is the OpenAI-compatible "natural completion" finish_reason; if we
    # see "length" the test should bump max_tokens, not silently pass.
    assert response.stop_reason == "stop", (
        f"got stop_reason={response.stop_reason!r}; consider raising max_tokens"
    )


@pytest.mark.asyncio
async def test_ollama_emits_audit_inside_charter(tmp_path: Path) -> None:
    """A live Ollama call inside a Charter must emit started + completed audit entries."""
    contract = _make_contract(tmp_path)
    provider = OpenAICompatibleProvider.for_ollama(
        base_url=f"{_OLLAMA_URL_BASE}/v1",
    )

    with Charter(contract, tools=ToolRegistry()):
        response = await provider.complete(
            prompt="Say the word PONG and nothing else.",
            model_pin=_OLLAMA_MODEL,
            max_tokens=1500,
            temperature=0.0,
        )

    assert response.text.strip()

    audit_lines = (tmp_path / "ws" / "audit.jsonl").read_text().splitlines()
    actions = [_action(line) for line in audit_lines]
    assert "llm_call_started" in actions
    assert "llm_call_completed" in actions

    completed_idx = actions.index("llm_call_completed")
    completed_payload = _payload(audit_lines[completed_idx])
    assert completed_payload["provider_id"] == "ollama"
    assert completed_payload["model_pin"] == _OLLAMA_MODEL
    assert completed_payload["input_tokens"] > 0
    assert completed_payload["output_tokens"] > 0


def _make_contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="live ollama smoke",
        required_outputs=["findings.json"],
        budget=BudgetSpec(
            llm_calls=10,
            tokens=10000,
            wall_clock_sec=120.0,
            cloud_api_calls=10,
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


def _action(line: str) -> str:
    import json

    return str(json.loads(line)["action"])


def _payload(line: str) -> dict[str, Any]:
    import json

    return dict(json.loads(line)["payload"])
