"""Tests — `meta_harness.skill_judge` (Hermes Phase 2 LLM-judge, additive adjudication).

Two contracts pinned here:

1. ``adjudicate_with_judge`` keeps the **pass-rate hard floor**: a win/loss is decided
   deterministically; the judge is consulted only on a tie and only shifts toward DSPy.
2. ``judge_skill_candidates`` is **defensive**: provider error / unparseable / categorical
   violation all collapse to ``TIE`` (abstain → legacy default), and it honours the bounded
   retry (at most one extra attempt).
"""

from __future__ import annotations

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from meta_harness.skill_judge import (
    JudgeVerdict,
    adjudicate_with_judge,
    judge_skill_candidates,
)


def _resp(text: str) -> LLMResponse:
    return LLMResponse(text=text, stop_reason="end_turn", usage=TokenUsage(0, 0), model_pin="m")


# --------------------------------------------------------------- pure adjudicator (the floor)


def test_dspy_strict_win_decided_by_floor_without_judge() -> None:
    md, meta = adjudicate_with_judge(0.5, 0.9, "LEGACY", "DSPY", verdict=None)
    assert md == "DSPY"
    assert meta["winner"] == "dspy"
    assert meta["adjudication"] == "pass_rate"


def test_dspy_regression_blocked_even_if_judge_prefers_dspy() -> None:
    # Hard floor: a pass-rate regression can never be promoted, judge notwithstanding.
    md, meta = adjudicate_with_judge(0.9, 0.5, "LEGACY", "DSPY", verdict=JudgeVerdict.PREFER_DSPY)
    assert md == "LEGACY"
    assert meta["winner"] == "legacy"
    assert meta["adjudication"] == "pass_rate"


def test_tie_default_legacy_without_judge() -> None:
    md, meta = adjudicate_with_judge(1.0, 1.0, "LEGACY", "DSPY", verdict=None)
    assert md == "LEGACY"
    assert meta["winner"] == "legacy"
    assert meta["adjudication"] == "tie_default_legacy"


def test_tie_judge_prefers_dspy_promotes() -> None:
    md, meta = adjudicate_with_judge(1.0, 1.0, "LEGACY", "DSPY", verdict=JudgeVerdict.PREFER_DSPY)
    assert md == "DSPY"
    assert meta["winner"] == "dspy"
    assert meta["adjudication"] == "llm_judge"
    assert meta["judge_verdict"] == "prefer_dspy"


def test_tie_judge_prefers_legacy_keeps_legacy() -> None:
    md, meta = adjudicate_with_judge(1.0, 1.0, "LEGACY", "DSPY", verdict=JudgeVerdict.PREFER_LEGACY)
    assert md == "LEGACY"
    assert meta["winner"] == "legacy"
    assert meta["adjudication"] == "llm_judge"


def test_tie_judge_abstains_keeps_legacy() -> None:
    md, meta = adjudicate_with_judge(1.0, 1.0, "LEGACY", "DSPY", verdict=JudgeVerdict.TIE)
    assert md == "LEGACY"
    assert meta["winner"] == "legacy"


# --------------------------------------------------------------- the LLM-judge (defensive)


@pytest.mark.asyncio
async def test_judge_parses_b_as_prefer_dspy() -> None:
    provider = FakeLLMProvider([_resp("B")])
    verdict = await judge_skill_candidates(
        provider, legacy_skill_md="L", dspy_skill_md="D", agent_id="investigation", category="x"
    )
    assert verdict is JudgeVerdict.PREFER_DSPY


@pytest.mark.asyncio
async def test_judge_parses_a_as_prefer_legacy() -> None:
    provider = FakeLLMProvider([_resp("A\n")])
    verdict = await judge_skill_candidates(
        provider, legacy_skill_md="L", dspy_skill_md="D", agent_id="investigation", category="x"
    )
    assert verdict is JudgeVerdict.PREFER_LEGACY


@pytest.mark.asyncio
async def test_judge_retries_once_then_succeeds() -> None:
    provider = FakeLLMProvider([_resp("hmm not sure"), _resp("B")])
    verdict = await judge_skill_candidates(
        provider, legacy_skill_md="L", dspy_skill_md="D", agent_id="investigation", category="x"
    )
    assert verdict is JudgeVerdict.PREFER_DSPY
    assert len(provider.calls) == 2  # initial + one bounded retry


@pytest.mark.asyncio
async def test_judge_unparseable_after_retry_abstains() -> None:
    provider = FakeLLMProvider([_resp("maybe"), _resp("dunno")])
    verdict = await judge_skill_candidates(
        provider, legacy_skill_md="L", dspy_skill_md="D", agent_id="investigation", category="x"
    )
    assert verdict is JudgeVerdict.TIE
    assert len(provider.calls) == 2  # never exceeds the bounded-retry cap


@pytest.mark.asyncio
async def test_judge_provider_error_abstains() -> None:
    class _Boom:
        provider_id = "boom"
        model_class = None

        async def complete(self, **_kw: object) -> LLMResponse:
            raise RuntimeError("transport down")

    verdict = await judge_skill_candidates(
        _Boom(),  # type: ignore[arg-type]
        legacy_skill_md="L",
        dspy_skill_md="D",
        agent_id="investigation",
        category="x",
    )
    assert verdict is JudgeVerdict.TIE


@pytest.mark.asyncio
async def test_judge_categorical_violation_abstains() -> None:
    # A reply echoing plaintext PII violates the categorical-only contract → abstain.
    provider = FakeLLMProvider([_resp("B because the user 123-45-6789 needs it")])
    verdict = await judge_skill_candidates(
        provider, legacy_skill_md="L", dspy_skill_md="D", agent_id="investigation", category="x"
    )
    assert verdict is JudgeVerdict.TIE
