"""LLM-driven hypothesis synthesizer (D.7 Task 11).

The **load-bearing LLM surface** in D.7 — the only Nexus agent so far
where LLM use is critical to output quality (D.1-D.3 + F.3 + F.6 treat
the LLM as a UX nicety; D.7's hypothesis-generation is core).

Per ADR-007 v1.1, no per-agent `llm.py`. The synthesizer calls the
`charter.llm.LLMProvider` Protocol directly (the agent driver
constructs providers via `charter.llm_adapter.make_provider`).

**Three load-bearing properties:**

1. **Evidence validation is mandatory.** Every hypothesis the LLM
   emits must reference real audit_event / finding IDs from the
   collected input. Unresolved refs → drop the hypothesis + log a
   warning. NEVER let fabricated evidence ride into the report. A
   hypothesis where ANY ref is unresolved drops in full — D.7 won't
   emit a hypothesis where some evidence is real and some is
   hallucinated.

2. **LLM unavailable / malformed → deterministic fallback.** The
   fallback emits one hypothesis per finding with confidence 0.5 and
   `statement = finding title`. The audit chain + timeline are
   unaffected; only the hypothesis section's richness suffers.

3. **Deterministic on identical inputs.** The fallback produces the
   exact same `Hypothesis` objects (same hypothesis_id, statement,
   evidence_refs) given the same findings. Critical for the eval
   runner (Task 14) and for cross-tenant reproducibility.

The LLM is prompted with the NLAH bundle (loaded via
`investigation.nlah_loader.load_system_prompt()`) which carries the
6-stage pipeline + sub-agent flavors + the expected hypothesis JSON
shape.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from typing import Any

from audit.schemas import AuditEvent
from charter.llm import LLMProvider
from pydantic import ValidationError

from investigation.nlah_loader import load_system_prompt
from investigation.schemas import Hypothesis, Timeline
from investigation.tools.related_findings import RelatedFinding

_LOG = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_DEFAULT_MODEL_PIN = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 2048


async def synthesize_hypotheses(
    *,
    llm_provider: LLMProvider | None,
    audit_events: Sequence[AuditEvent],
    related_findings: Sequence[RelatedFinding],
    timeline: Timeline | None,
) -> tuple[Hypothesis, ...]:
    """Generate hypotheses from collected evidence.

    LLM-driven when `llm_provider` is set; deterministic-fallback
    otherwise. Every emitted hypothesis carries fully-resolved
    `evidence_refs` — hallucinated refs cause the hypothesis to drop.
    """
    evidence_index = _build_evidence_index(audit_events, related_findings)

    if llm_provider is None:
        return _deterministic_fallback(related_findings)

    try:
        response = await llm_provider.complete(
            prompt=_build_prompt(audit_events, related_findings, timeline),
            system=load_system_prompt(),
            model_pin=_DEFAULT_MODEL_PIN,
            max_tokens=_MAX_TOKENS,
            temperature=0.0,
        )
    except Exception as exc:
        _LOG.warning("LLM synthesize failed; using deterministic fallback: %s", exc)
        return _deterministic_fallback(related_findings)

    parsed = _parse_response(response.text)
    if parsed is None or not parsed:
        # Either malformed JSON or LLM returned `{"hypotheses": []}`.
        return _deterministic_fallback(related_findings)

    validated: list[Hypothesis] = []
    for raw in parsed:
        h = _build_hypothesis(raw, evidence_index=evidence_index)
        if h is not None:
            validated.append(h)

    # If validation drops everything (full hallucination), fall back so
    # the operator still gets something to look at.
    if not validated:
        return _deterministic_fallback(related_findings)
    return tuple(validated)


# ---------------------------- internals ---------------------------------


def _build_evidence_index(
    audit_events: Sequence[AuditEvent],
    related_findings: Sequence[RelatedFinding],
) -> frozenset[str]:
    """The set of valid evidence_ref values for the current investigation."""
    refs: set[str] = set()
    for ae in audit_events:
        refs.add(f"audit_event:{ae.entry_hash[:16]}")
    for rf in related_findings:
        uid = str((rf.payload.get("finding_info") or {}).get("uid", ""))
        if uid:
            refs.add(f"finding:{uid}")
    return frozenset(refs)


def _build_prompt(
    audit_events: Sequence[AuditEvent],
    related_findings: Sequence[RelatedFinding],
    timeline: Timeline | None,
) -> str:
    """Render the evidence corpus as a compact prompt body."""
    lines: list[str] = []
    lines.append("Generate forensic hypotheses for this incident.")
    lines.append('Respond with a JSON object: {"hypotheses": [...]}.')
    lines.append(
        'Each hypothesis: {"hypothesis_id": str, "statement": str, '
        '"confidence": float (0..1), "evidence_refs": [str, ...]}.'
    )
    lines.append("evidence_refs values must be drawn from the corpus below.")
    lines.append("")

    if audit_events:
        lines.append("AUDIT EVENTS:")
        for ae in audit_events:
            lines.append(
                f"- audit_event:{ae.entry_hash[:16]} | agent={ae.agent_id} | "
                f"action={ae.action} | payload={json.dumps(ae.payload)}"
            )
        lines.append("")

    if related_findings:
        lines.append("RELATED FINDINGS:")
        for rf in related_findings:
            uid = str((rf.payload.get("finding_info") or {}).get("uid", ""))
            title = str((rf.payload.get("finding_info") or {}).get("title", ""))
            lines.append(
                f"- finding:{uid} | source_agent={rf.source_agent} | "
                f"class_uid={rf.class_uid} | title={title!r}"
            )
        lines.append("")

    if timeline is not None and timeline.events:
        lines.append("TIMELINE:")
        for ev in timeline.events:
            lines.append(
                f"- {ev.emitted_at.isoformat()} | {ev.actor} | {ev.action} | ref={ev.evidence_ref}"
            )

    return "\n".join(lines)


def _parse_response(text: str) -> list[dict[str, Any]] | None:
    """Return the parsed `hypotheses` list, or None on parse failure."""
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
    hypotheses = parsed.get("hypotheses")
    if not isinstance(hypotheses, list):
        return None
    return hypotheses


def _build_hypothesis(
    raw: Any,
    *,
    evidence_index: frozenset[str],
) -> Hypothesis | None:
    if not isinstance(raw, dict):
        return None
    refs_raw = raw.get("evidence_refs", [])
    if not isinstance(refs_raw, list) or not refs_raw:
        return None
    refs = tuple(str(r) for r in refs_raw)
    # ANY unresolved ref → drop the whole hypothesis.
    for ref in refs:
        if ref not in evidence_index:
            _LOG.warning(
                "dropping hypothesis %s — evidence_ref %s not in collected corpus",
                raw.get("hypothesis_id", "<no-id>"),
                ref,
            )
            return None

    try:
        return Hypothesis(
            hypothesis_id=str(raw.get("hypothesis_id", "")),
            statement=str(raw.get("statement", "")),
            confidence=float(raw.get("confidence", 0.0)),
            evidence_refs=refs,
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _deterministic_fallback(
    related_findings: Sequence[RelatedFinding],
) -> tuple[Hypothesis, ...]:
    """One hypothesis per finding, confidence 0.5, statement = title."""
    out: list[Hypothesis] = []
    for rf in related_findings:
        finding_info = rf.payload.get("finding_info") or {}
        uid = str(finding_info.get("uid", ""))
        if not uid:
            continue
        title = str(finding_info.get("title") or rf.payload.get("class_name") or "finding")
        try:
            h = Hypothesis(
                hypothesis_id=f"H-{uid}",
                statement=f"Evidence: {title}",
                confidence=0.5,
                evidence_refs=(f"finding:{uid}",),
            )
        except (ValidationError, ValueError):
            continue
        out.append(h)
    return tuple(out)


__all__ = ["synthesize_hypotheses"]
