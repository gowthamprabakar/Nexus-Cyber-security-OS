"""Tests — `meta_harness.dspy_flip_gate` (Hermes Phase 4b Gate 3 flip-criterion).

The flip gate is the honesty boundary on ``NEXUS_DSPY_PRODUCTION``: it codifies *when* a flip
is authorized and refuses to authorize on absence-of-evidence. These tests pin that contract.
"""

from __future__ import annotations

from meta_harness.dspy_flip_gate import (
    MIN_DELTA_AGENTS,
    MIN_QUALITY_DELTA,
    FlipEvidence,
    FlipGate,
    evaluate_flip_readiness,
    render_flip_status_markdown,
)


def test_default_evidence_is_not_authorized() -> None:
    """No measured delta + Task-14 unvalidated → not authorized (no production by faith)."""
    readiness = evaluate_flip_readiness()
    assert readiness.authorized is False
    # Gates 1 & 2 (T2 + cadence) are met today; Gate 3 + Task-14 block.
    assert set(readiness.unmet) == {FlipGate.QUALITY_DELTA, FlipGate.TASK_14_ANTHROPIC}


def test_t2_and_cadence_met_by_default() -> None:
    readiness = evaluate_flip_readiness()
    met = {g.gate for g in readiness.gates if g.met}
    assert FlipGate.T2_TRACE_PERSISTENCE in met
    assert FlipGate.VOLUME_CADENCE in met


def test_missing_t2_blocks() -> None:
    readiness = evaluate_flip_readiness(FlipEvidence(t2_trace_persistence_available=False))
    assert FlipGate.T2_TRACE_PERSISTENCE in readiness.unmet
    assert readiness.authorized is False


def test_quality_delta_below_threshold_blocks() -> None:
    readiness = evaluate_flip_readiness(
        FlipEvidence(
            measured_quality_delta=MIN_QUALITY_DELTA - 0.01,
            measured_delta_agent_count=MIN_DELTA_AGENTS + 5,
            task_14_anthropic_validated=True,
        )
    )
    assert FlipGate.QUALITY_DELTA in readiness.unmet


def test_quality_delta_too_few_agents_blocks() -> None:
    readiness = evaluate_flip_readiness(
        FlipEvidence(
            measured_quality_delta=MIN_QUALITY_DELTA + 0.5,
            measured_delta_agent_count=MIN_DELTA_AGENTS - 1,
            task_14_anthropic_validated=True,
        )
    )
    assert FlipGate.QUALITY_DELTA in readiness.unmet


def test_task_14_unvalidated_blocks_even_with_strong_delta() -> None:
    readiness = evaluate_flip_readiness(
        FlipEvidence(
            measured_quality_delta=0.9,
            measured_delta_agent_count=MIN_DELTA_AGENTS + 10,
            task_14_anthropic_validated=False,
        )
    )
    assert readiness.authorized is False
    assert FlipGate.TASK_14_ANTHROPIC in readiness.unmet


def test_all_gates_met_authorizes() -> None:
    readiness = evaluate_flip_readiness(
        FlipEvidence(
            measured_quality_delta=MIN_QUALITY_DELTA,
            measured_delta_agent_count=MIN_DELTA_AGENTS,
            task_14_anthropic_validated=True,
        )
    )
    assert readiness.authorized is True
    assert readiness.unmet == ()


def test_render_markdown_reports_verdict_and_blockers() -> None:
    md = render_flip_status_markdown(evaluate_flip_readiness())
    assert "NOT AUTHORIZED" in md
    assert "quality_delta" in md
    assert "task_14_anthropic" in md
    authorized_md = render_flip_status_markdown(
        evaluate_flip_readiness(
            FlipEvidence(
                measured_quality_delta=1.0,
                measured_delta_agent_count=MIN_DELTA_AGENTS,
                task_14_anthropic_validated=True,
            )
        )
    )
    assert "flip AUTHORIZED" in authorized_md
