"""Stage 3 HYPOTHESIZE — single-call LLM orchestration.

D.12 is the second LLM-driven agent in the fleet (after D.13).
Unlike D.13's three-call structure (outline -> per-section -> exec
summary), D.12 issues **one** LLM call per run: given the
deterministic ``CoverageGap`` list from Stage 2, the LLM proposes
the hypothesis + probe-directive text grounded in each gap.

Per ADR-006 (LLM adapter) + ADR-007 v1.1 (no per-agent ``llm.py``),
the hypothesizer talks to ``charter.llm.LLMProvider`` directly.

**Short-circuit on empty gaps.** When the gap-detector returns
nothing (a clean run), the hypothesizer skips the LLM call entirely
and returns an empty draft. This is the cheap, common case — most
scan windows will be gap-free.

**Q6 retry hint.** When Stage 4 REVIEW (Task 7) rejects the draft
for classifier-substring leakage, the driver re-enters with
``q6_violation_retry_hint=True``. The hypothesizer appends a
``[Q6 RETRY]`` banner to the prompt mirroring D.13's narrator.

Typed errors:

- ``HypothesizerError`` — base class for all hypothesizer failures.
- ``HypothesisCallError`` — raised when the LLM JSON is malformed
  or fails schema validation. The driver catches this and emits a
  fallback "hypothesis generation failed" claim (no fabricated
  hypotheses on a malformed LLM response).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from charter.llm import LLMProvider
from pydantic import ValidationError

from curiosity.prompts import load_prompt
from curiosity.schemas import CoverageGap, CuriosityDraft, Hypothesis

_LOG = logging.getLogger(__name__)

# Default model pin. Workhorse tier — same as D.13. Frontier tier
# is overkill for the structured-output hypothesis task; edge tier
# may struggle with the JSON-only constraint.
DEFAULT_MODEL_PIN = "claude-haiku-4-5-20251001"

_HYPOTHESIS_MAX_TOKENS = 2048

# Per-run cap (mirrors curiosity.schemas._MAX_HYPOTHESES_PER_RUN).
# When the LLM emits more than this, the hypothesizer truncates
# silently + logs a warning rather than letting the schema raise.
_MAX_HYPOTHESES_PER_RUN = 5

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

_Q6_RETRY_BANNER = (
    "\n\n[Q6 RETRY] A previous hypothesis attempt produced classifier-shaped "
    "substrings (SSN / credit-card / AWS-access-key / JWT). DO NOT produce "
    "such substrings again. Refer to data categorically by classifier label, "
    "never by value."
)


class HypothesizerError(Exception):
    """Base class for hypothesizer-side typed failures."""


class HypothesisCallError(HypothesizerError):
    """The LLM call returned malformed JSON or failed schema validation."""


async def hypothesize(
    *,
    llm_provider: LLMProvider,
    gaps: tuple[CoverageGap, ...],
    model_pin: str = DEFAULT_MODEL_PIN,
    q6_violation_retry_hint: bool = False,
) -> CuriosityDraft:
    """Run the single-call HYPOTHESIZE stage against ``llm_provider``.

    Short-circuits to an empty draft when ``gaps`` is empty (no LLM
    call). Otherwise issues one ``LLMProvider.complete()`` call;
    parses the response as JSON; validates against the
    ``Hypothesis`` pydantic schema; truncates to
    ``_MAX_HYPOTHESES_PER_RUN``.

    Raises:
        HypothesisCallError: LLM call failed, JSON malformed, or
            schema validation failed. The driver (Task 10) catches
            this and emits a fallback claim.
    """
    if not gaps:
        _LOG.info("hypothesizer: no coverage gaps; short-circuit to empty draft")
        return CuriosityDraft()

    system = load_prompt("hypothesis")
    user_payload = {"coverage_gaps": [g.model_dump(mode="json") for g in gaps]}
    user_text = json.dumps(user_payload, default=str)
    if q6_violation_retry_hint:
        user_text = user_text + _Q6_RETRY_BANNER

    try:
        response = await llm_provider.complete(
            system=system,
            prompt=user_text,
            model_pin=model_pin,
            max_tokens=_HYPOTHESIS_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        raise HypothesisCallError(f"hypothesis LLM call failed: {exc}") from exc

    parsed = _parse_json_object(response.text)
    if parsed is None:
        raise HypothesisCallError("hypothesis call returned non-JSON output")

    raw_hypotheses = parsed.get("hypotheses")
    if not isinstance(raw_hypotheses, list):
        raise HypothesisCallError(
            "hypothesis JSON missing top-level 'hypotheses' array "
            f"(got keys: {sorted(parsed.keys())!r})"
        )

    validated: list[Hypothesis] = []
    for idx, raw in enumerate(raw_hypotheses):
        try:
            validated.append(Hypothesis.model_validate(raw))
        except ValidationError as exc:
            raise HypothesisCallError(
                f"hypothesis index {idx} failed schema validation: {exc}"
            ) from exc

    if len(validated) > _MAX_HYPOTHESES_PER_RUN:
        _LOG.warning(
            "hypothesizer: LLM emitted %d hypotheses (cap %d); truncating",
            len(validated),
            _MAX_HYPOTHESES_PER_RUN,
        )
        validated = validated[:_MAX_HYPOTHESES_PER_RUN]

    return CuriosityDraft(
        hypotheses=tuple(validated),
        llm_call_count=1,
        total_tokens_used=response.usage.total_tokens,
    )


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from LLM output, tolerating ```json fences."""
    stripped = text.strip()
    if not stripped:
        return None
    match = _FENCE_RE.search(stripped)
    candidate = match.group(1) if match else stripped
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


__all__ = [
    "DEFAULT_MODEL_PIN",
    "HypothesisCallError",
    "HypothesizerError",
    "hypothesize",
]
