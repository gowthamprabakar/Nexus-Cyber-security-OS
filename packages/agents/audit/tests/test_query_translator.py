"""Tests for `audit.query_translator` (F.6 Task 11) — NL → typed params.

The translator is the only LLM-using surface in F.6. Operators ask the
CLI in natural language ("show me every entity upsert for tenant X in
the last 24 hours"); the translator converts that into a typed
`AuditQueryArgs` shape the agent driver feeds into `AuditStore.query`.

Production contract:

- Returns an `AuditQueryArgs` with at minimum the supplied `tenant_id`.
- LLM is told (via the NLAH system prompt) to emit a JSON object
  matching the `AuditQueryArgs` shape. The translator parses it,
  validating each field.
- Graceful fallback: if the LLM emits non-JSON, the translator returns
  `AuditQueryArgs(tenant_id=<supplied>)` — equivalent to "show me
  everything" — so a flaky LLM doesn't break the operator workflow.
- LLM unavailable (provider=None) returns the same fallback shape.
- Anti-pattern guard: the audit package must NOT ship its own llm.py;
  it goes through `charter.llm_adapter`. (Covered in `test_smoke.py`.)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from audit.query_translator import AuditQueryArgs, translate_nl_query
from charter.llm import LLMResponse, TokenUsage, ToolSchema

_TENANT_A = "01HV0T0000000000000000TENA"


class _StubLLMProvider:
    """Lightweight test double — yields a configured `LLMResponse` string."""

    provider_id = "stub"

    def __init__(self, response_text: str) -> None:
        self._response_text = response_text

    @property
    def model_class(self) -> Any:
        from charter.llm import ModelTier

        return ModelTier.WORKHORSE

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
        return LLMResponse(
            text=self._response_text,
            stop_reason="end_turn",
            usage=TokenUsage(input_tokens=1, output_tokens=1),
            model_pin=model_pin,
            provider_id=self.provider_id,
        )


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_translate_returns_typed_args_with_tenant() -> None:
    provider = _StubLLMProvider(
        response_text='{"action": "episode_appended", "agent_id": "cloud_posture"}'
    )
    args = await translate_nl_query(
        nl="show me every episode appended by cloud_posture",
        tenant_id=_TENANT_A,
        provider=provider,
    )
    assert isinstance(args, AuditQueryArgs)
    assert args.tenant_id == _TENANT_A
    assert args.action == "episode_appended"
    assert args.agent_id == "cloud_posture"


@pytest.mark.asyncio
async def test_translate_parses_time_window_strings() -> None:
    payload = '{"since": "2026-05-01T00:00:00Z", "until": "2026-05-31T23:59:59Z"}'
    provider = _StubLLMProvider(response_text=payload)
    args = await translate_nl_query(
        nl="every action in May 2026",
        tenant_id=_TENANT_A,
        provider=provider,
    )
    assert args.since == datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC)
    assert args.until == datetime(2026, 5, 31, 23, 59, 59, tzinfo=UTC)


@pytest.mark.asyncio
async def test_translate_parses_correlation_id_filter() -> None:
    provider = _StubLLMProvider(response_text='{"correlation_id": "01J7N4Y0A2L9SQWRJK3U9ECIGA"}')
    args = await translate_nl_query(
        nl="anything for correlation 01J7N4Y0A2L9SQWRJK3U9ECIGA",
        tenant_id=_TENANT_A,
        provider=provider,
    )
    assert args.correlation_id == "01J7N4Y0A2L9SQWRJK3U9ECIGA"


@pytest.mark.asyncio
async def test_translate_tenant_in_llm_output_is_ignored() -> None:
    """The translator stamps `tenant_id` from the caller — the LLM cannot
    pivot the query to a different tenant. (Defence-in-depth on top of RLS.)
    """
    other_tenant = "01HV0T0000000000000000OTHR"
    provider = _StubLLMProvider(response_text=f'{{"tenant_id": "{other_tenant}"}}')
    args = await translate_nl_query(
        nl="cross-tenant peek attempt",
        tenant_id=_TENANT_A,
        provider=provider,
    )
    assert args.tenant_id == _TENANT_A


# ---------------------------- code-fence tolerance ---------------------


@pytest.mark.asyncio
async def test_translate_strips_markdown_code_fences() -> None:
    """LLMs love to wrap JSON in ```json fences; the translator pulls the
    JSON body out before parsing.
    """
    fenced = '```json\n{"action": "entity_upserted"}\n```'
    provider = _StubLLMProvider(response_text=fenced)
    args = await translate_nl_query(
        nl="entity upserts",
        tenant_id=_TENANT_A,
        provider=provider,
    )
    assert args.action == "entity_upserted"


# ---------------------------- fallbacks --------------------------------


@pytest.mark.asyncio
async def test_translate_falls_back_to_tenant_only_when_llm_unavailable() -> None:
    """`provider=None` → no LLM call; return the everything-for-tenant query."""
    args = await translate_nl_query(
        nl="any natural language",
        tenant_id=_TENANT_A,
        provider=None,
    )
    assert args.tenant_id == _TENANT_A
    assert args.action is None
    assert args.agent_id is None
    assert args.since is None
    assert args.until is None
    assert args.correlation_id is None


@pytest.mark.asyncio
async def test_translate_falls_back_on_malformed_llm_output() -> None:
    """Non-JSON LLM output: degrade to the everything-for-tenant query."""
    provider = _StubLLMProvider(response_text="I'm sorry, I can't help with that.")
    args = await translate_nl_query(nl="show me audits", tenant_id=_TENANT_A, provider=provider)
    assert args.tenant_id == _TENANT_A
    assert args.action is None
    assert args.since is None


@pytest.mark.asyncio
async def test_translate_falls_back_on_invalid_field_types() -> None:
    """LLM emits JSON but `since` is not parseable as ISO datetime —
    drop just that field; keep the parts that are usable.
    """
    provider = _StubLLMProvider(
        response_text='{"action": "episode_appended", "since": "yesterday"}'
    )
    args = await translate_nl_query(nl="...", tenant_id=_TENANT_A, provider=provider)
    assert args.action == "episode_appended"
    assert args.since is None


# ---------------------------- pydantic shape ---------------------------


def test_audit_query_args_is_frozen() -> None:
    from pydantic import ValidationError

    args = AuditQueryArgs(tenant_id=_TENANT_A)
    with pytest.raises(ValidationError):
        args.action = "x"  # type: ignore[misc]
