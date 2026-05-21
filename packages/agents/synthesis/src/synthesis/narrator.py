"""Stage 3 NARRATE — LLM-call orchestration.

D.13's **load-bearing LLM surface**. v0.1 is the first agent in the
fleet that actually calls the LLM in its hot path — prior agents
(F.3 / D.1 / D.3 / D.4 / D.5 / D.6 / D.7 / D.8 / multi-cloud / k8s /
A.1) plumb ``llm_provider`` through their drivers but never invoke
it. D.13 closes that loop.

Per ADR-006 (LLM adapter) + ADR-007 v1.1 (no per-agent ``llm.py``),
the narrator talks to ``charter.llm.LLMProvider`` directly. The agent
driver (Task 9) constructs providers via
``charter.llm_adapter.make_provider``.

**Three-call structure** (Q4 of the D.13 plan):

1. **Outline call** — given the ENRICH-stage ``ContextBundle``,
   produce a structured ``SynthesisOutline`` (JSON: section list +
   per-section ``cited_finding_ids`` + ``overall_narrative_intent``).
   Validated against the pydantic schema. Bad JSON / shape failure
   raises ``OutlineCallError``; the driver emits a fallback narrative.

2. **Per-section narration calls** — one inner call per validated
   outline section. Returns markdown body text. Per-section failure
   is **forgiving** (per plan §Risks): drops a placeholder body for
   that one section and continues with siblings. NEVER raises out.

3. **Executive summary call** — given the validated outline + the
   original context bundle, produce the 1-paragraph C-suite digest +
   key-metrics dict. Validated against ``ExecutiveSummary`` schema;
   shape failure raises ``ExecutiveSummaryCallError``.

All three calls pin ``temperature=0.0``. Prompt templates loaded via
``synthesis.prompts.load_prompt`` (Task 5).

**Q6 retry hint.** When Stage 4 REVIEW (Task 7) rejects the narrative
for a classifier-substring violation, the driver re-enters with
``q6_violation_retry_hint=True``. The narrator inflates each per-
section prompt with a "Q6 RETRY" banner so the LLM doesn't repeat
the leak. See plan §Q6 + WI-2.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from charter.llm import LLMProvider
from pydantic import ValidationError

from synthesis.prompts import load_prompt
from synthesis.schemas import (
    ContextBundle,
    ExecutiveSummary,
    NarrativeSection,
    OutlineSection,
    SynthesisOutline,
)

_LOG = logging.getLogger(__name__)

# Default model pin for v0.1 narrator calls. The driver (Task 9) may
# override via the ``model_pin`` kwarg. Workhorse-tier is the right
# default for narrative work — frontier-tier is overkill for prose
# summarisation, edge-tier may struggle with structured-JSON outputs.
_DEFAULT_MODEL_PIN = "claude-haiku-4-5-20251001"

_OUTLINE_MAX_TOKENS = 2048
_NARRATION_MAX_TOKENS = 1500
_EXECUTIVE_SUMMARY_MAX_TOKENS = 1024

# Placeholder rendered when per-section narration fails. The reviewer
# treats this string as a known non-narrative artefact (not a Q6
# violation; just a degraded but legal output).
_PER_SECTION_PLACEHOLDER = "[section narration unavailable]"

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

_Q6_RETRY_BANNER = (
    "\n\n[Q6 RETRY] A previous narration attempt produced classifier-shaped "
    "substrings (SSN / credit-card / AWS-access-key / JWT). DO NOT produce "
    "such substrings again. Refer to data categorically by classifier label, "
    "never by value."
)


class NarratorError(Exception):
    """Base class for narrator-side typed failures."""


class OutlineCallError(NarratorError):
    """The outline call returned malformed JSON or shape failed validation."""


class NarrationCallError(NarratorError):
    """A per-section narration call failed.

    Per plan §Risks, the narrator does NOT raise this out — it logs
    and emits a placeholder body. The error type exists for the
    audit log + for tests that introspect a single section call.
    """


class ExecutiveSummaryCallError(NarratorError):
    """The executive-summary call returned malformed JSON or shape failed."""


@dataclass(frozen=True, slots=True)
class SynthesisDraft:
    """In-flight Stage 3 NARRATE output.

    Stage 4 REVIEW (Task 7) inspects the draft; Stage 5 SUMMARIZE
    (Task 9 driver) assembles the final ``SynthesisReport`` from
    these fields + the run-level metadata (customer_id, run_id,
    scan timestamps).
    """

    outline: SynthesisOutline
    sections: tuple[NarrativeSection, ...]
    executive_summary: ExecutiveSummary
    llm_call_count: int = 0
    total_tokens_used: int = 0
    section_failures: tuple[str, ...] = field(default_factory=tuple)


async def narrate(
    *,
    llm_provider: LLMProvider,
    context_bundle: ContextBundle,
    model_pin: str = _DEFAULT_MODEL_PIN,
    q6_violation_retry_hint: bool = False,
) -> SynthesisDraft:
    """Run the 3-call NARRATE pipeline against ``llm_provider``.

    Raises:
        OutlineCallError: outline-call JSON malformed or schema fails.
        ExecutiveSummaryCallError: exec-summary JSON malformed or
            schema fails. Per-section failure does NOT raise (see
            ``SynthesisDraft.section_failures``).
    """
    bundle_json = _context_bundle_to_json(context_bundle)

    outline, outline_usage = await _call_outline(
        llm_provider=llm_provider,
        bundle_json=bundle_json,
        model_pin=model_pin,
    )

    sections: list[NarrativeSection] = []
    failures: list[str] = []
    section_call_count = 0
    section_tokens = 0
    for outline_section in outline.sections:
        section_call_count += 1
        try:
            body, usage = await _call_narration(
                llm_provider=llm_provider,
                bundle_json=bundle_json,
                outline_section=outline_section,
                model_pin=model_pin,
                q6_violation_retry_hint=q6_violation_retry_hint,
            )
            section_tokens += usage
        except NarrationCallError as exc:
            _LOG.warning(
                "per-section narration failed for heading %r: %s; emitting placeholder body",
                outline_section.heading,
                exc,
            )
            body = _PER_SECTION_PLACEHOLDER
            failures.append(outline_section.heading)
        sections.append(
            NarrativeSection(
                heading=outline_section.heading,
                body=body,
                cited_finding_ids=list(outline_section.cited_finding_ids),
            )
        )

    exec_summary, exec_usage = await _call_executive_summary(
        llm_provider=llm_provider,
        bundle_json=bundle_json,
        outline=outline,
        model_pin=model_pin,
    )

    return SynthesisDraft(
        outline=outline,
        sections=tuple(sections),
        executive_summary=exec_summary,
        llm_call_count=1 + section_call_count + 1,
        total_tokens_used=outline_usage + section_tokens + exec_usage,
        section_failures=tuple(failures),
    )


# ---------------------------------------------------------------------------
# Outline call
# ---------------------------------------------------------------------------


async def _call_outline(
    *,
    llm_provider: LLMProvider,
    bundle_json: str,
    model_pin: str,
) -> tuple[SynthesisOutline, int]:
    system = load_prompt("outline")
    try:
        response = await llm_provider.complete(
            system=system,
            prompt=bundle_json,
            model_pin=model_pin,
            max_tokens=_OUTLINE_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        raise OutlineCallError(f"outline LLM call failed: {exc}") from exc

    parsed = _parse_json_object(response.text)
    if parsed is None:
        raise OutlineCallError("outline call returned non-JSON output")
    try:
        outline = SynthesisOutline.model_validate(parsed)
    except ValidationError as exc:
        raise OutlineCallError(f"outline JSON failed schema validation: {exc}") from exc
    return outline, response.usage.total_tokens


# ---------------------------------------------------------------------------
# Per-section narration call
# ---------------------------------------------------------------------------


async def _call_narration(
    *,
    llm_provider: LLMProvider,
    bundle_json: str,
    outline_section: OutlineSection,
    model_pin: str,
    q6_violation_retry_hint: bool,
) -> tuple[str, int]:
    system = load_prompt("narration")
    user_payload = {
        "context_bundle": json.loads(bundle_json),
        "section": {
            "heading": outline_section.heading,
            "intent": outline_section.intent,
            "cited_finding_ids": list(outline_section.cited_finding_ids),
        },
    }
    user_text = json.dumps(user_payload, default=str)
    if q6_violation_retry_hint:
        user_text = user_text + _Q6_RETRY_BANNER

    try:
        response = await llm_provider.complete(
            system=system,
            prompt=user_text,
            model_pin=model_pin,
            max_tokens=_NARRATION_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        raise NarrationCallError(f"narration LLM call failed: {exc}") from exc

    body = response.text.strip()
    if not body:
        raise NarrationCallError("narration call returned empty body")
    return body, response.usage.total_tokens


# ---------------------------------------------------------------------------
# Executive summary call
# ---------------------------------------------------------------------------


async def _call_executive_summary(
    *,
    llm_provider: LLMProvider,
    bundle_json: str,
    outline: SynthesisOutline,
    model_pin: str,
) -> tuple[ExecutiveSummary, int]:
    system = load_prompt("executive_summary")
    user_payload = {
        "context_bundle": json.loads(bundle_json),
        "outline": {
            "overall_narrative_intent": outline.overall_narrative_intent,
            "sections": [
                {
                    "heading": s.heading,
                    "intent": s.intent,
                    "cited_finding_ids": list(s.cited_finding_ids),
                }
                for s in outline.sections
            ],
        },
    }
    user_text = json.dumps(user_payload, default=str)
    try:
        response = await llm_provider.complete(
            system=system,
            prompt=user_text,
            model_pin=model_pin,
            max_tokens=_EXECUTIVE_SUMMARY_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        raise ExecutiveSummaryCallError(f"executive_summary LLM call failed: {exc}") from exc

    parsed = _parse_json_object(response.text)
    if parsed is None:
        raise ExecutiveSummaryCallError("executive_summary call returned non-JSON output")
    try:
        exec_summary = ExecutiveSummary.model_validate(parsed)
    except ValidationError as exc:
        raise ExecutiveSummaryCallError(
            f"executive_summary JSON failed schema validation: {exc}"
        ) from exc
    return exec_summary, response.usage.total_tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _context_bundle_to_json(bundle: ContextBundle) -> str:
    """Serialise the ContextBundle to a deterministic JSON string for the LLM."""
    return bundle.model_dump_json()


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
    "ExecutiveSummaryCallError",
    "NarrationCallError",
    "NarratorError",
    "OutlineCallError",
    "SynthesisDraft",
    "narrate",
]
