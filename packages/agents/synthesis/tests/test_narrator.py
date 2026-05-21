"""Tests — ``synthesis.narrator`` (Task 6).

The narrator is D.13's load-bearing LLM surface. Tests use the
``charter.llm.FakeLLMProvider`` test double (canned responses
returned in order) to keep the LLM out of the loop.

Coverage:
1. Happy path — outline + per-section + executive summary all return
   well-formed JSON / markdown; ``SynthesisDraft`` round-trips.
2. Outline-call error paths — malformed JSON / non-dict / schema
   violation all raise ``OutlineCallError``.
3. Per-section narration is **forgiving** — exceptions / empty body
   produce a placeholder ``[section narration unavailable]`` body
   and the heading is recorded in ``section_failures``.
4. Executive-summary error paths — malformed JSON / schema fail
   raise ``ExecutiveSummaryCallError``.
5. Q6 retry banner is appended to per-section prompts when
   ``q6_violation_retry_hint=True``.
6. Token accounting + LLM call count are tracked across all 3 call
   types (WI-1 budget consumption probe).
7. ``temperature=0.0`` is always passed to ``complete()``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from synthesis.narrator import (
    ExecutiveSummaryCallError,
    NarrationCallError,
    NarratorError,
    OutlineCallError,
    SynthesisDraft,
    narrate,
)
from synthesis.schemas import ContextBundle


def _bundle(**overrides: object) -> ContextBundle:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "scan_window_start": datetime(2026, 5, 21, tzinfo=UTC),
        "scan_window_end": datetime(2026, 5, 21, 1, tzinfo=UTC),
        "investigation_conclusions": [],
        "compliance_failures": [],
        "cloud_posture_findings": [],
        "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "total_findings": 1,
    }
    defaults.update(overrides)
    return ContextBundle(**defaults)  # type: ignore[arg-type]


def _resp(text: str, *, input_tokens: int = 100, output_tokens: int = 50) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        model_pin="claude-haiku-4-5-20251001",
    )


def _outline_json(sections: int = 2) -> str:
    section_list = [
        {
            "heading": f"Section {i + 1}",
            "intent": f"Section {i + 1} intent",
            "cited_finding_ids": [f"CSPM-AWS-{i + 1:03d}"],
        }
        for i in range(sections)
    ]
    return json.dumps(
        {"overall_narrative_intent": "Cover the key findings.", "sections": section_list}
    )


def _exec_summary_json() -> str:
    return json.dumps(
        {
            "paragraph": (
                "The 2026-05-21 scan window surfaced one high-severity finding "
                "in the IAM posture. The compliance posture is largely intact."
            ),
            "key_metrics": {
                "total_findings": 1,
                "critical": 0,
                "high": 1,
                "top_failing_control": "1.10",
            },
        }
    )


def _happy_provider(outline_sections: int = 2) -> FakeLLMProvider:
    """Returns 1 outline + N narrations + 1 exec summary in order."""
    responses = [_resp(_outline_json(outline_sections))]
    for i in range(outline_sections):
        responses.append(_resp(f"Body of section {i + 1} - operator-grade prose."))
    responses.append(_resp(_exec_summary_json()))
    return FakeLLMProvider(responses)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_narrate_happy_path_returns_draft() -> None:
    provider = _happy_provider(outline_sections=2)
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())

    assert isinstance(draft, SynthesisDraft)
    assert len(draft.sections) == 2
    assert draft.sections[0].heading == "Section 1"
    assert "Body of section 1" in draft.sections[0].body
    assert draft.sections[0].cited_finding_ids == ["CSPM-AWS-001"]
    assert draft.executive_summary.key_metrics["total_findings"] == 1
    assert draft.executive_summary.key_metrics["top_failing_control"] == "1.10"
    assert draft.section_failures == ()


@pytest.mark.asyncio
async def test_narrate_tracks_llm_call_count() -> None:
    """1 outline + N narration + 1 exec_summary = 2 + N calls total."""
    provider = _happy_provider(outline_sections=3)
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())

    assert draft.llm_call_count == 5  # 1 + 3 + 1
    assert len(provider.calls) == 5


@pytest.mark.asyncio
async def test_narrate_tracks_total_tokens() -> None:
    """Each canned response has 100+50 = 150 tokens; 5 calls -> 750 tokens."""
    provider = _happy_provider(outline_sections=3)
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())

    assert draft.total_tokens_used == 750


@pytest.mark.asyncio
async def test_narrate_passes_temperature_zero() -> None:
    """All LLM calls must pin temperature=0.0 (Q4 of the plan)."""
    provider = _happy_provider(outline_sections=1)
    await narrate(llm_provider=provider, context_bundle=_bundle())

    for call in provider.calls:
        assert call["temperature"] == 0.0


@pytest.mark.asyncio
async def test_narrate_passes_model_pin_to_every_call() -> None:
    provider = _happy_provider(outline_sections=1)
    await narrate(llm_provider=provider, context_bundle=_bundle(), model_pin="custom-model-pin")

    for call in provider.calls:
        assert call["model_pin"] == "custom-model-pin"


@pytest.mark.asyncio
async def test_narrate_outline_call_receives_outline_system_prompt() -> None:
    """The outline call's `system` is the outline.md template."""
    provider = _happy_provider(outline_sections=1)
    await narrate(llm_provider=provider, context_bundle=_bundle())

    outline_call = provider.calls[0]
    assert "Outline Call" in (outline_call["system"] or "")


# ---------------------------------------------------------------------------
# Outline call error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_outline_malformed_json_raises_outline_call_error() -> None:
    provider = FakeLLMProvider([_resp("this is not JSON at all")])
    with pytest.raises(OutlineCallError, match="non-JSON"):
        await narrate(llm_provider=provider, context_bundle=_bundle())


@pytest.mark.asyncio
async def test_outline_non_dict_json_raises_outline_call_error() -> None:
    """LLM returns a JSON array instead of a JSON object."""
    provider = FakeLLMProvider([_resp('["not", "an", "object"]')])
    with pytest.raises(OutlineCallError):
        await narrate(llm_provider=provider, context_bundle=_bundle())


@pytest.mark.asyncio
async def test_outline_schema_violation_raises_outline_call_error() -> None:
    """LLM returns JSON missing required `overall_narrative_intent`."""
    bad = json.dumps({"sections": [{"heading": "x", "intent": "y"}]})
    provider = FakeLLMProvider([_resp(bad)])
    with pytest.raises(OutlineCallError, match="schema"):
        await narrate(llm_provider=provider, context_bundle=_bundle())


@pytest.mark.asyncio
async def test_outline_fenced_json_is_extracted() -> None:
    """LLM wraps JSON in a ```json code fence — narrator strips it."""
    fenced = f"Sure, here's the outline:\n```json\n{_outline_json(1)}\n```\n"
    provider = FakeLLMProvider(
        [
            _resp(fenced),
            _resp("Section 1 body"),
            _resp(_exec_summary_json()),
        ]
    )
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())
    assert len(draft.sections) == 1


class _ScriptedProvider:
    """Stand-in stub that raises on the Nth call and returns from the iterator otherwise."""

    provider_id = "scripted"

    def __init__(self, responses: list[LLMResponse | Exception]) -> None:
        self._iter = iter(responses)
        self.calls: list[dict[str, object]] = []

    @property
    def model_class(self) -> object:
        from charter.llm import ModelTier

        return ModelTier.WORKHORSE

    async def complete(self, **kwargs: object) -> LLMResponse:
        self.calls.append(kwargs)
        nxt = next(self._iter)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


@pytest.mark.asyncio
async def test_outline_provider_exception_raises_outline_call_error() -> None:
    """The provider itself raises (network blip etc.) -> typed error."""
    provider = _ScriptedProvider([RuntimeError("simulated provider failure")])
    with pytest.raises(OutlineCallError, match="failed"):
        await narrate(llm_provider=provider, context_bundle=_bundle())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_narration_provider_exception_emits_placeholder() -> None:
    """Provider blowup mid-narration -> placeholder body, no raise."""
    provider = _ScriptedProvider(
        [
            _resp(_outline_json(2)),
            RuntimeError("network blip"),
            _resp("Body 2"),
            _resp(_exec_summary_json()),
        ]
    )
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())  # type: ignore[arg-type]
    assert draft.sections[0].body == "[section narration unavailable]"
    assert draft.sections[1].body == "Body 2"
    assert draft.section_failures == ("Section 1",)


@pytest.mark.asyncio
async def test_exec_summary_provider_exception_raises() -> None:
    """Provider blowup during exec summary -> ExecutiveSummaryCallError."""
    provider = _ScriptedProvider(
        [
            _resp(_outline_json(1)),
            _resp("Section 1 body"),
            RuntimeError("network blip"),
        ]
    )
    with pytest.raises(ExecutiveSummaryCallError, match="failed"):
        await narrate(llm_provider=provider, context_bundle=_bundle())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Per-section narration — forgiving fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_narration_empty_body_emits_placeholder_does_not_raise() -> None:
    """LLM returns empty narration body for one section -> placeholder."""
    provider = FakeLLMProvider(
        [
            _resp(_outline_json(2)),
            _resp("Section 1 body"),
            _resp("   "),  # whitespace-only -> empty body
            _resp(_exec_summary_json()),
        ]
    )
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())

    assert draft.sections[0].body == "Section 1 body"
    assert draft.sections[1].body == "[section narration unavailable]"
    assert draft.section_failures == ("Section 2",)


@pytest.mark.asyncio
async def test_one_section_failure_does_not_block_other_sections() -> None:
    """Plan §Risks: 'sibling sections still render'."""
    provider = FakeLLMProvider(
        [
            _resp(_outline_json(3)),
            _resp("Body 1"),
            _resp(""),
            _resp("Body 3"),
            _resp(_exec_summary_json()),
        ]
    )
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())

    assert draft.sections[0].body == "Body 1"
    assert draft.sections[1].body == "[section narration unavailable]"
    assert draft.sections[2].body == "Body 3"
    assert len(draft.section_failures) == 1


@pytest.mark.asyncio
async def test_q6_retry_hint_appends_banner_to_per_section_prompt() -> None:
    """When q6_violation_retry_hint=True, narration prompts carry the banner."""
    provider = _happy_provider(outline_sections=1)
    await narrate(
        llm_provider=provider,
        context_bundle=_bundle(),
        q6_violation_retry_hint=True,
    )

    # provider.calls = [outline, narration, exec_summary]
    narration_call = provider.calls[1]
    assert "[Q6 RETRY]" in narration_call["prompt"]
    # Outline + exec_summary calls don't get the banner.
    assert "[Q6 RETRY]" not in (provider.calls[0]["prompt"] or "")
    assert "[Q6 RETRY]" not in (provider.calls[2]["prompt"] or "")


@pytest.mark.asyncio
async def test_q6_retry_hint_default_false_no_banner_in_prompts() -> None:
    provider = _happy_provider(outline_sections=2)
    await narrate(llm_provider=provider, context_bundle=_bundle())
    for call in provider.calls:
        assert "[Q6 RETRY]" not in (call["prompt"] or "")


# ---------------------------------------------------------------------------
# Executive summary error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exec_summary_malformed_json_raises() -> None:
    provider = FakeLLMProvider(
        [
            _resp(_outline_json(1)),
            _resp("Section 1 body"),
            _resp("not json"),
        ]
    )
    with pytest.raises(ExecutiveSummaryCallError, match="non-JSON"):
        await narrate(llm_provider=provider, context_bundle=_bundle())


@pytest.mark.asyncio
async def test_exec_summary_schema_violation_raises() -> None:
    """LLM returns JSON missing `paragraph`."""
    provider = FakeLLMProvider(
        [
            _resp(_outline_json(1)),
            _resp("Section 1 body"),
            _resp(json.dumps({"key_metrics": {}})),  # missing paragraph
        ]
    )
    with pytest.raises(ExecutiveSummaryCallError, match="schema"):
        await narrate(llm_provider=provider, context_bundle=_bundle())


# ---------------------------------------------------------------------------
# Cited-id preservation across the pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cited_finding_ids_preserved_from_outline_to_sections() -> None:
    """Plan §Task 6: cited_finding_ids flow verbatim from outline to section."""
    outline = json.dumps(
        {
            "overall_narrative_intent": "Cover findings.",
            "sections": [
                {
                    "heading": "Identity posture",
                    "intent": "Identity issues",
                    "cited_finding_ids": ["CSPM-IAM-A", "CSPM-IAM-B", "CSPM-IAM-C"],
                }
            ],
        }
    )
    provider = FakeLLMProvider(
        [
            _resp(outline),
            _resp("Identity body"),
            _resp(_exec_summary_json()),
        ]
    )
    draft = await narrate(llm_provider=provider, context_bundle=_bundle())
    assert draft.sections[0].cited_finding_ids == ["CSPM-IAM-A", "CSPM-IAM-B", "CSPM-IAM-C"]


# ---------------------------------------------------------------------------
# Type hierarchy / exports
# ---------------------------------------------------------------------------


def test_typed_errors_inherit_from_narrator_error() -> None:
    """Driver (Task 9) catches `NarratorError` to handle all three uniformly."""
    assert issubclass(OutlineCallError, NarratorError)
    assert issubclass(NarrationCallError, NarratorError)
    assert issubclass(ExecutiveSummaryCallError, NarratorError)
