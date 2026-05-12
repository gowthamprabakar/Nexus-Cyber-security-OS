"""Tests for `investigation.synthesizer` (D.7 Task 11).

The LLM-driven hypothesis generation surface. **First agent for which
LLM use is load-bearing** (D.1-D.3 + F.3 + F.6 use the LLM as a UX
nicety; D.7's hypothesis quality depends on it).

Production contract:

- `synthesize_hypotheses(*, llm_provider, audit_events, related_findings,
  timeline)` → `tuple[Hypothesis, ...]`.
- LLM is prompted with the NLAH bundle + the collected evidence; it
  emits JSON matching the documented shape; the synthesizer parses,
  validates, and returns.
- **Evidence validation is mandatory.** Each hypothesis's
  `evidence_refs` must resolve against the union of:
  - `audit_event:<entry_hash[:16]>` for each AuditEvent in the input
  - `finding:<finding_info.uid>` for each RelatedFinding in the input
  - `entity:<entity_id>` (Phase 1c when SemanticStore returns are
    plumbed through — Task 12).
- Unresolved refs → drop the hypothesis + log a warning.
- LLM unavailable / malformed JSON / no hypotheses returned → fallback
  to one deterministic hypothesis per finding (confidence 0.5,
  statement = finding title).
- Idempotent: same input → same output.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from audit.schemas import AuditEvent
from charter.llm import LLMResponse, TokenUsage, ToolSchema
from investigation.synthesizer import synthesize_hypotheses
from investigation.tools.related_findings import RelatedFinding

_TENANT_A = "01HV0T0000000000000000TENA"


def _audit_event(*, seed: int, action: str = "x") -> AuditEvent:
    h_prev = f"{seed:064x}"
    h_entry = f"{seed + 1:064x}"
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action=action,
        payload={"seed": seed},
        previous_hash=h_prev,
        entry_hash=h_entry,
        emitted_at=datetime(2026, 5, 12, tzinfo=UTC),
        source=f"jsonl:fixture/{seed}",
    )


def _related_finding(*, uid: str, title: str = "Public bucket") -> RelatedFinding:
    return RelatedFinding(
        source_agent="cloud_posture",
        source_run_id="run-001",
        class_uid=2003,
        payload={
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "finding_info": {"uid": uid, "title": title},
            "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
        },
    )


class _StubLLMProvider:
    """Returns a fixed text response — used to test the parser surface."""

    provider_id = "stub"

    def __init__(self, *, response_text: str) -> None:
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


# ---------------------------- LLM unavailable → fallback --------------


@pytest.mark.asyncio
async def test_llm_none_falls_back_to_one_hypothesis_per_finding() -> None:
    findings = (
        _related_finding(uid="F-1", title="Public S3 bucket"),
        _related_finding(uid="F-2", title="IAM key leaked"),
    )
    hypotheses = await synthesize_hypotheses(
        llm_provider=None,
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    assert len(hypotheses) == 2
    statements = {h.statement for h in hypotheses}
    assert any("Public S3 bucket" in s for s in statements)
    assert any("IAM key leaked" in s for s in statements)
    # All fallback hypotheses use confidence 0.5.
    assert all(h.confidence == 0.5 for h in hypotheses)
    # Every fallback hypothesis references its source finding.
    assert all(any(ref.startswith("finding:") for ref in h.evidence_refs) for h in hypotheses)


@pytest.mark.asyncio
async def test_llm_none_with_no_findings_returns_empty() -> None:
    """Without findings, the fallback path has nothing to enumerate."""
    hypotheses = await synthesize_hypotheses(
        llm_provider=None,
        audit_events=(),
        related_findings=(),
        timeline=None,
    )
    assert hypotheses == ()


@pytest.mark.asyncio
async def test_llm_failure_falls_back() -> None:
    """LLM provider raises → fallback path."""

    class _BadLLM:
        provider_id = "bad"

        @property
        def model_class(self) -> Any:
            from charter.llm import ModelTier

            return ModelTier.WORKHORSE

        async def complete(self, **kwargs: Any) -> Any:
            raise RuntimeError("LLM unreachable")

    findings = (_related_finding(uid="F-1"),)
    hypotheses = await synthesize_hypotheses(
        llm_provider=_BadLLM(),
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    assert len(hypotheses) == 1


# ---------------------------- LLM happy path -----------------------


@pytest.mark.asyncio
async def test_llm_returns_valid_hypotheses_with_resolved_refs() -> None:
    audit = _audit_event(seed=1, action="finding.created")
    findings = (_related_finding(uid="F-1"),)
    audit_ref = f"audit_event:{audit.entry_hash[:16]}"

    response = (
        '{"hypotheses": [{'
        '"hypothesis_id": "H-001",'
        '"statement": "The IAM key was compromised then used to expose S3.",'
        '"confidence": 0.8,'
        f'"evidence_refs": ["{audit_ref}", "finding:F-1"]'
        "}]}"
    )

    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text=response),
        audit_events=(audit,),
        related_findings=findings,
        timeline=None,
    )
    assert len(hypotheses) == 1
    h = hypotheses[0]
    assert h.hypothesis_id == "H-001"
    assert h.confidence == 0.8
    assert audit_ref in h.evidence_refs
    assert "finding:F-1" in h.evidence_refs


@pytest.mark.asyncio
async def test_llm_strips_markdown_code_fences() -> None:
    audit = _audit_event(seed=1)
    audit_ref = f"audit_event:{audit.entry_hash[:16]}"

    response = (
        '```json\n{"hypotheses":[{"hypothesis_id":"H-1","statement":"x",'
        f'"confidence":0.5,"evidence_refs":["{audit_ref}"]}}]}}\n```'
    )

    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text=response),
        audit_events=(audit,),
        related_findings=(),
        timeline=None,
    )
    assert len(hypotheses) == 1


# ---------------------------- evidence validation --------------------


@pytest.mark.asyncio
async def test_drops_hypothesis_with_unresolved_evidence_ref() -> None:
    """An LLM-generated hypothesis pointing at non-existent audit_event /
    finding is a hallucination. Drop it.
    """
    audit = _audit_event(seed=1)
    audit_ref = f"audit_event:{audit.entry_hash[:16]}"
    response = (
        '{"hypotheses":['
        f'{{"hypothesis_id":"H-good","statement":"real","confidence":0.7,"evidence_refs":["{audit_ref}"]}},'
        '{"hypothesis_id":"H-bad","statement":"hallucinated","confidence":0.9,"evidence_refs":["audit_event:deadbeefdeadbeef"]}'
        "]}"
    )
    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text=response),
        audit_events=(audit,),
        related_findings=(),
        timeline=None,
    )
    # Hallucinated one is dropped; real one stays.
    assert len(hypotheses) == 1
    assert hypotheses[0].hypothesis_id == "H-good"


@pytest.mark.asyncio
async def test_drops_hypothesis_with_partially_resolved_refs() -> None:
    """If ANY ref doesn't resolve, drop the whole hypothesis — D.7 won't
    emit a hypothesis where some of the evidence is fabricated.
    """
    audit = _audit_event(seed=1)
    audit_ref = f"audit_event:{audit.entry_hash[:16]}"
    response = (
        '{"hypotheses":[{'
        '"hypothesis_id":"H-1","statement":"x","confidence":0.8,'
        f'"evidence_refs":["{audit_ref}", "finding:NONEXISTENT"]'
        "}]}"
    )
    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text=response),
        audit_events=(audit,),
        related_findings=(),
        timeline=None,
    )
    assert hypotheses == ()


# ---------------------------- malformed LLM output -------------------


@pytest.mark.asyncio
async def test_malformed_llm_json_falls_back() -> None:
    findings = (_related_finding(uid="F-1"),)
    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text="not even close to JSON"),
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    # Fallback emits one per finding.
    assert len(hypotheses) == 1


@pytest.mark.asyncio
async def test_llm_returns_empty_hypotheses_array_falls_back() -> None:
    findings = (_related_finding(uid="F-1"),)
    hypotheses = await synthesize_hypotheses(
        llm_provider=_StubLLMProvider(response_text='{"hypotheses": []}'),
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    assert len(hypotheses) == 1


# ---------------------------- determinism ----------------------------


@pytest.mark.asyncio
async def test_fallback_is_deterministic_across_calls() -> None:
    """Same fallback input → same output (same hypothesis_ids, statements)."""
    findings = (_related_finding(uid="F-1"), _related_finding(uid="F-2"))
    a = await synthesize_hypotheses(
        llm_provider=None,
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    b = await synthesize_hypotheses(
        llm_provider=None,
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    assert a == b


# ---------------------------- output shape ---------------------------


@pytest.mark.asyncio
async def test_returns_tuple_of_hypothesis() -> None:
    from investigation.schemas import Hypothesis

    findings = (_related_finding(uid="F-1"),)
    hypotheses = await synthesize_hypotheses(
        llm_provider=None,
        audit_events=(),
        related_findings=findings,
        timeline=None,
    )
    assert isinstance(hypotheses, tuple)
    assert all(isinstance(h, Hypothesis) for h in hypotheses)
