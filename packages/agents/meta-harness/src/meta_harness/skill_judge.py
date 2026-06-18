"""LLM-judge adjudication — Hermes Phase 2 (additive, above the pass-rate floor).

The deterministic ``adjudicate_pass_rates`` comparison is the **hard floor**: a DSPy candidate
that regresses on eval-gate pass-rate can *never* be promoted, and a DSPy candidate that
strictly beats legacy on pass-rate wins outright — the judge is not consulted in either case.

This judge is **additive**: it is consulted only where the deterministic floor is *ambiguous* —
when the two candidates **tie** on pass-rate (commonly both at 1.0). Today a tie defaults to
legacy (safety default); the judge can break that tie toward DSPy on qualitative merit, and only
toward DSPy — a judge that prefers legacy or abstains leaves the safety default untouched. The
judge therefore can only ever *add* DSPy promotions; it can never demote a pass-rate winner nor
rescue a pass-rate loser. Pass-rate stays the hard floor.

Anthropic-style LLM-as-judge: a single categorical comparison ("A", "B", or "TIE"), with the
two shared LLM invariants enforced — ``assert_categorical_only`` (no plaintext PII echoed into
the verdict) + ``assert_bounded_retry`` (at most one retry). Any error, ambiguity, or contract
violation collapses to :data:`JudgeVerdict.TIE` (abstain → legacy safety default) so the judge
never breaks or skews a run.

Default-OFF: the lifecycle only consults the judge when explicitly enabled (the whole DSPy path
is itself gated behind ``NEXUS_DSPY_PRODUCTION``). Capability, not a flag flip.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from charter.llm import LLMProvider
from nexus_runtime.llm_invariants.bounded import MAX_ATTEMPTS, assert_bounded_retry
from nexus_runtime.llm_invariants.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)

_LOG = logging.getLogger(__name__)

#: Opt-in env flag (default-OFF). Even when set, the judge only acts inside the DSPy path,
#: which is itself gated behind ``NEXUS_DSPY_PRODUCTION`` — so this is a no-op until both are on.
ENV_LLM_JUDGE = "NEXUS_DSPY_LLM_JUDGE"

#: Workhorse tier — a two-candidate preference is well-shaped; no frontier capability needed.
DEFAULT_JUDGE_MODEL_PIN = "claude-sonnet-4-6"
DEFAULT_JUDGE_MAX_TOKENS = 64


class JudgeVerdict(Enum):
    """Categorical outcome of the LLM-judge comparison."""

    PREFER_DSPY = "prefer_dspy"
    PREFER_LEGACY = "prefer_legacy"
    TIE = "tie"  # abstain → caller's safety default (legacy)


# Legacy is presented as candidate A, DSPy as candidate B (fixed, deterministic mapping —
# no randomness available in this runtime; the judge sees neutral A/B labels, not provenance).
_JUDGE_SYSTEM = (
    "You are an impartial judge comparing two operational SKILL definitions for a security "
    "agent. Decide which is the better skill: clearer trigger, sounder tool sequence, more "
    "actionable guidance. Refer to any sensitive data categorically (by label such as [SSN]), "
    "never by value. Answer with EXACTLY ONE token on a single line: 'A', 'B', or 'TIE'."
)


def _build_judge_prompt(*, agent_id: str, category: str, legacy_md: str, dspy_md: str) -> str:
    return (
        f"Agent: {agent_id}\nSkill category: {category}\n\n"
        f"=== Candidate A ===\n{legacy_md}\n\n"
        f"=== Candidate B ===\n{dspy_md}\n\n"
        "Which candidate is the better skill? Answer 'A', 'B', or 'TIE'."
    )


def _parse_verdict(text: str) -> JudgeVerdict | None:
    """Map a categorical reply to a verdict, or ``None`` if it is not parseable.

    Strict: the reply (stripped, upper-cased, first token) must be exactly A / B / TIE.
    Anything else returns ``None`` so the caller retries once then abstains.
    """
    first = text.strip().upper().split()[0] if text.strip() else ""
    first = first.strip(".'\"`*")
    if first == "A":
        return JudgeVerdict.PREFER_LEGACY
    if first == "B":
        return JudgeVerdict.PREFER_DSPY
    if first == "TIE":
        return JudgeVerdict.TIE
    return None


async def judge_skill_candidates(
    provider: LLMProvider,
    *,
    legacy_skill_md: str,
    dspy_skill_md: str,
    agent_id: str,
    category: str,
    model_pin: str = DEFAULT_JUDGE_MODEL_PIN,
) -> JudgeVerdict:
    """Ask the LLM which candidate is better; return a categorical verdict.

    Defensive by construction: a provider error, an unparseable reply after the bounded retry,
    or a categorical-contract violation all collapse to :data:`JudgeVerdict.TIE` (abstain). The
    judge never raises and never skews a run — the worst case is "no opinion → legacy default".
    """
    prompt = _build_judge_prompt(
        agent_id=agent_id, category=category, legacy_md=legacy_skill_md, dspy_md=dspy_skill_md
    )
    attempt = 0
    while True:
        attempt += 1
        try:
            assert_bounded_retry(attempt)  # hard cap: initial + at most one retry
        except Exception:  # exhausted the bound → abstain
            _LOG.info("skill_judge.abstain agent_id=%s reason=retry_exhausted", agent_id)
            return JudgeVerdict.TIE
        try:
            response = await provider.complete(
                prompt=prompt,
                model_pin=model_pin,
                max_tokens=DEFAULT_JUDGE_MAX_TOKENS,
                system=_JUDGE_SYSTEM,
                temperature=0.0,
            )
            assert_categorical_only(response.text)
            verdict = _parse_verdict(response.text)
        except CategoricalContractViolationError:
            _LOG.warning("skill_judge.abstain agent_id=%s reason=categorical_violation", agent_id)
            return JudgeVerdict.TIE
        except Exception as exc:  # provider/transport error → abstain (legacy default)
            _LOG.warning("skill_judge.abstain agent_id=%s reason=provider_error: %s", agent_id, exc)
            return JudgeVerdict.TIE
        if verdict is not None:
            _LOG.info("skill_judge.verdict agent_id=%s verdict=%s", agent_id, verdict.value)
            return verdict
        if attempt >= MAX_ATTEMPTS:  # last parse failed → abstain
            _LOG.info("skill_judge.abstain agent_id=%s reason=unparseable", agent_id)
            return JudgeVerdict.TIE
        # else: loop once more (the single bounded retry)


def adjudicate_with_judge(
    legacy_pass_rate: float,
    dspy_pass_rate: float,
    legacy_skill_md: str,
    dspy_skill_md: str,
    *,
    verdict: JudgeVerdict | None,
) -> tuple[str, dict[str, Any]]:
    """Pass-rate floor first, LLM-judge additive only on a tie (Phase 2).

    Mirrors :func:`meta_harness.dspy_skill_creator.adjudicate_pass_rates` exactly when
    ``verdict`` is ``None`` — the deterministic floor decides:

    * DSPy strictly beats legacy → DSPy wins (floor; judge irrelevant).
    * DSPy regresses → legacy wins (hard floor; judge never rescues a loser).
    * Tie → legacy by safety default.

    The judge is consulted *only* on a tie, and can shift the outcome *only* toward DSPy
    (``PREFER_DSPY``). ``PREFER_LEGACY`` / ``TIE`` / ``None`` keep the legacy safety default.
    Returns ``(winning_skill_md, metadata)``.
    """
    delta = dspy_pass_rate - legacy_pass_rate
    if dspy_pass_rate > legacy_pass_rate:
        winner, winning_md, adjudication = "dspy", dspy_skill_md, "pass_rate"
    elif dspy_pass_rate < legacy_pass_rate:
        winner, winning_md, adjudication = "legacy", legacy_skill_md, "pass_rate"
    elif verdict is JudgeVerdict.PREFER_DSPY:
        winner, winning_md, adjudication = "dspy", dspy_skill_md, "llm_judge"
    else:
        winner, winning_md = "legacy", legacy_skill_md
        adjudication = "llm_judge" if verdict is not None else "tie_default_legacy"
    return winning_md, {
        "winner": winner,
        "legacy_pass_rate": legacy_pass_rate,
        "dspy_pass_rate": dspy_pass_rate,
        "delta": delta,
        "adjudication": adjudication,
        "judge_verdict": verdict.value if verdict is not None else None,
    }


__all__ = [
    "DEFAULT_JUDGE_MAX_TOKENS",
    "DEFAULT_JUDGE_MODEL_PIN",
    "ENV_LLM_JUDGE",
    "JudgeVerdict",
    "adjudicate_with_judge",
    "judge_skill_candidates",
]
