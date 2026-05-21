"""Tests — `curiosity.hypothesizer` (Task 6).

The hypothesizer is D.12's single-call LLM surface. Tests use the
`charter.llm.FakeLLMProvider` test double for canned responses.

Coverage:
1. Empty gaps -> short-circuit (no LLM call).
2. Happy path: valid JSON with hypotheses -> CuriosityDraft.
3. Malformed JSON -> HypothesisCallError.
4. Non-object JSON (array) -> HypothesisCallError.
5. Missing "hypotheses" key -> HypothesisCallError.
6. Schema-failing hypothesis (statement too long etc.) -> HypothesisCallError.
7. LLM returns >5 hypotheses -> truncated with warning log.
8. Q6 retry banner appears in prompt when retry_hint=True.
9. Q6 retry banner absent when retry_hint=False.
10. temperature=0.0 always passed.
11. model_pin passed through.
12. LLM provider exception -> wrapped as HypothesisCallError.
13. llm_call_count tracked.
14. total_tokens_used tracked.
15. JSON-fence tolerated (```json {...} ```).
16. Typed errors inherit from HypothesizerError.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from curiosity.hypothesizer import (
    DEFAULT_MODEL_PIN,
    HypothesisCallError,
    HypothesizerError,
    hypothesize,
)
from curiosity.schemas import CoverageGap, CuriosityDraft, ProbeAction, TargetAgent


def _gap(
    region: str = "us-east-1",
    *,
    asset_count: int = 50,
    days: int = 60,
    severity: str = "medium",
) -> CoverageGap:
    return CoverageGap(
        region=region,
        asset_count=asset_count,
        days_since_last_finding=days,
        severity_hint=severity,
    )


def _resp(text: str, *, input_tokens: int = 100, output_tokens: int = 50) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        model_pin=DEFAULT_MODEL_PIN,
    )


def _valid_hypothesis_json(count: int = 1) -> str:
    """Build a JSON payload with N valid hypotheses."""
    hypotheses = []
    for i in range(count):
        hypotheses.append(
            {
                "statement": f"Region us-east-{i + 1} appears under-scanned.",
                "rationale": (
                    f"Region us-east-{i + 1} has assets but no findings in the "
                    "scan window. This is consistent with either clean posture "
                    "or a coverage gap. Recommend running D.5 across the region "
                    "to establish a baseline."
                ),
                "probe_directive": {
                    "target_agent": TargetAgent.DATA_SECURITY.value,
                    "target_resource_arn": f"arn:aws:s3:::region-{i + 1}-bucket",
                    "action": ProbeAction.SCAN.value,
                    "rationale_ref": "",
                },
                "cited_gap": {
                    "region": f"us-east-{i + 1}",
                    "asset_count": 50,
                    "days_since_last_finding": 60,
                    "severity_hint": "medium",
                },
            }
        )
    return json.dumps({"hypotheses": hypotheses})


# ---------------------------------------------------------------------------
# Short-circuit on empty gaps
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_gaps_short_circuit_no_llm_call() -> None:
    provider = FakeLLMProvider([])  # no canned responses; would raise if called
    draft = await hypothesize(llm_provider=provider, gaps=())

    assert isinstance(draft, CuriosityDraft)
    assert draft.hypotheses == ()
    assert draft.llm_call_count == 0
    assert draft.total_tokens_used == 0
    assert provider.calls == []


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_returns_curiosity_draft() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=2))])
    draft = await hypothesize(llm_provider=provider, gaps=(_gap(), _gap("eu-west-3")))

    assert len(draft.hypotheses) == 2
    assert draft.hypotheses[0].cited_gap.region == "us-east-1"
    assert draft.hypotheses[1].cited_gap.region == "us-east-2"
    assert draft.llm_call_count == 1
    assert draft.total_tokens_used == 150  # 100+50


# ---------------------------------------------------------------------------
# Malformed JSON paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_json_raises_hypothesis_call_error() -> None:
    provider = FakeLLMProvider([_resp("not JSON at all")])
    with pytest.raises(HypothesisCallError, match="non-JSON"):
        await hypothesize(llm_provider=provider, gaps=(_gap(),))


@pytest.mark.asyncio
async def test_non_dict_json_raises_hypothesis_call_error() -> None:
    """Top-level JSON array instead of object."""
    provider = FakeLLMProvider([_resp('["not", "an", "object"]')])
    with pytest.raises(HypothesisCallError):
        await hypothesize(llm_provider=provider, gaps=(_gap(),))


@pytest.mark.asyncio
async def test_missing_hypotheses_key_raises() -> None:
    """JSON object lacks the required 'hypotheses' array."""
    provider = FakeLLMProvider([_resp(json.dumps({"results": []}))])
    with pytest.raises(HypothesisCallError, match="hypotheses"):
        await hypothesize(llm_provider=provider, gaps=(_gap(),))


@pytest.mark.asyncio
async def test_schema_failing_hypothesis_raises() -> None:
    """LLM returns a hypothesis with statement over the 400-char cap."""
    bad = {
        "hypotheses": [
            {
                "statement": "x" * 401,  # over cap
                "rationale": "y" * 100,
                "probe_directive": {
                    "target_agent": "data_security",
                    "target_resource_arn": "arn:x",
                    "action": "scan",
                    "rationale_ref": "",
                },
                "cited_gap": {
                    "region": "us-east-1",
                    "asset_count": 50,
                    "days_since_last_finding": 60,
                    "severity_hint": "medium",
                },
            }
        ]
    }
    provider = FakeLLMProvider([_resp(json.dumps(bad))])
    with pytest.raises(HypothesisCallError, match="index 0"):
        await hypothesize(llm_provider=provider, gaps=(_gap(),))


# ---------------------------------------------------------------------------
# Truncation when LLM emits too many
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_more_than_five_hypotheses_truncated_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per _MAX_HYPOTHESES_PER_RUN=5; LLM emits 7 -> truncate to 5."""
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=7))])

    with caplog.at_level(logging.WARNING, logger="curiosity.hypothesizer"):
        draft = await hypothesize(llm_provider=provider, gaps=(_gap(),))

    assert len(draft.hypotheses) == 5
    assert any("truncating" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Q6 retry banner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_q6_retry_hint_appends_banner_to_prompt() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(
        llm_provider=provider,
        gaps=(_gap(),),
        q6_violation_retry_hint=True,
    )
    assert "[Q6 RETRY]" in provider.calls[0]["prompt"]


@pytest.mark.asyncio
async def test_q6_retry_hint_false_no_banner_in_prompt() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(llm_provider=provider, gaps=(_gap(),))
    assert "[Q6 RETRY]" not in provider.calls[0]["prompt"]


# ---------------------------------------------------------------------------
# Call shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_temperature_pinned_to_zero() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(llm_provider=provider, gaps=(_gap(),))
    assert provider.calls[0]["temperature"] == 0.0


@pytest.mark.asyncio
async def test_model_pin_passed_through() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(
        llm_provider=provider,
        gaps=(_gap(),),
        model_pin="custom-model-pin-x",
    )
    assert provider.calls[0]["model_pin"] == "custom-model-pin-x"


@pytest.mark.asyncio
async def test_default_model_pin_is_workhorse() -> None:
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(llm_provider=provider, gaps=(_gap(),))
    assert provider.calls[0]["model_pin"] == DEFAULT_MODEL_PIN


# ---------------------------------------------------------------------------
# Provider exceptions wrapped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_exception_wrapped_as_hypothesis_call_error() -> None:
    class _BlowupProvider:
        provider_id = "blowup"

        @property
        def model_class(self) -> object:
            from charter.llm import ModelTier

            return ModelTier.WORKHORSE

        async def complete(self, **kwargs: Any) -> LLMResponse:
            raise RuntimeError("simulated provider failure")

    with pytest.raises(HypothesisCallError, match="failed"):
        await hypothesize(llm_provider=_BlowupProvider(), gaps=(_gap(),))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# JSON-fence tolerance (mirror narrator's _parse_json_object)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fenced_json_is_extracted() -> None:
    """LLM wraps JSON in a ```json code fence — hypothesizer strips it."""
    fenced = f"Sure, here are the hypotheses:\n```json\n{_valid_hypothesis_json(count=1)}\n```\n"
    provider = FakeLLMProvider([_resp(fenced)])
    draft = await hypothesize(llm_provider=provider, gaps=(_gap(),))
    assert len(draft.hypotheses) == 1


# ---------------------------------------------------------------------------
# Token-accounting probe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_counts_propagate() -> None:
    """Total tokens = response.usage.total_tokens (input + output)."""
    provider = FakeLLMProvider(
        [_resp(_valid_hypothesis_json(count=1), input_tokens=500, output_tokens=200)]
    )
    draft = await hypothesize(llm_provider=provider, gaps=(_gap(),))
    assert draft.total_tokens_used == 700
    assert draft.llm_call_count == 1


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


def test_typed_errors_inherit_from_hypothesizer_error() -> None:
    """Driver (Task 10) catches HypothesizerError as the catch-all."""
    assert issubclass(HypothesisCallError, HypothesizerError)


# ---------------------------------------------------------------------------
# Gaps actually flow into the prompt payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coverage_gaps_serialized_into_user_prompt() -> None:
    """The Stage 2 gaps must reach the LLM. Verify via the prompt payload."""
    provider = FakeLLMProvider([_resp(_valid_hypothesis_json(count=1))])
    await hypothesize(
        llm_provider=provider,
        gaps=(_gap("eu-west-3", asset_count=42, days=35),),
    )
    prompt = provider.calls[0]["prompt"]
    assert "eu-west-3" in prompt
    assert "42" in prompt
    assert "35" in prompt
