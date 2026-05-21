"""Tests — ``synthesis.prompts`` (Task 5).

Validates:
1. The three prompt templates ship bundled and are loadable.
2. ``load_prompt`` accepts only the three valid names.
3. Key instructional sections are present in each template (no
   template silently shipped empty / missing the Q6 reminder /
   missing the schema spec).
"""

from __future__ import annotations

import pytest
from synthesis.prompts import load_prompt


def test_load_outline_returns_non_empty() -> None:
    text = load_prompt("outline")
    assert text.strip()
    assert "Synthesis Agent" in text
    assert "Outline Call" in text


def test_load_narration_returns_non_empty() -> None:
    text = load_prompt("narration")
    assert text.strip()
    assert "Narration Call" in text


def test_load_executive_summary_returns_non_empty() -> None:
    text = load_prompt("executive_summary")
    assert text.strip()
    assert "Executive Summary Call" in text


def test_unknown_prompt_name_raises_value_error() -> None:
    with pytest.raises(ValueError, match="unknown prompt template"):
        load_prompt("bogus")


def test_outline_template_specifies_json_output_schema() -> None:
    """Outline call must instruct the LLM to return JSON with sections +
    overall_narrative_intent fields. The schema spec is load-bearing for
    the narrator (Task 6)'s pydantic validation step."""
    text = load_prompt("outline")
    assert "overall_narrative_intent" in text
    assert "cited_finding_ids" in text
    assert "1-12 sections" in text or "1-12" in text


def test_narration_template_carries_q6_reminder() -> None:
    """The narration template MUST instruct the LLM to never reproduce
    classifier-matched substrings (SSN values, credit-card numbers, AWS
    access keys, JWTs). This is the first line of defence; the reviewer
    (Task 7) is the second."""
    text = load_prompt("narration")
    assert "Q6" in text
    assert "matched substring" in text.lower() or "matched substrings" in text.lower()
    # Specific classifier labels the LLM might be tempted to hallucinate.
    assert "SSN" in text
    assert "credit-card" in text.lower() or "credit card" in text.lower()
    assert "access key" in text.lower()


def test_executive_summary_template_carries_q6_reminder() -> None:
    """The executive summary is the highest-visibility output —
    matched-substring leakage here is the worst-case Q6 failure."""
    text = load_prompt("executive_summary")
    assert "Q6" in text
    assert "classifier-matched" in text.lower() or "matched substring" in text.lower()


def test_narration_template_caps_section_length() -> None:
    """The narration template must give the LLM a section-length budget
    (otherwise it may return novella-length sections that blow the
    LLM context budget on the next call)."""
    text = load_prompt("narration")
    assert "100-400 words" in text or "words" in text.lower()


def test_outline_template_no_prose_instruction() -> None:
    """The outline call must explicitly instruct the LLM to return JSON
    only (no preamble / explanation). Without this, the LLM often
    returns prose before the JSON object."""
    text = load_prompt("outline")
    assert "NO PROSE" in text or "JSON only" in text


def test_executive_summary_no_prose_instruction() -> None:
    """Same JSON-only constraint as the outline call."""
    text = load_prompt("executive_summary")
    assert "ONLY the JSON" in text or "JSON object" in text.lower()


def test_load_prompt_idempotent_across_calls() -> None:
    """Calling load_prompt repeatedly returns identical text (no in-place
    mutation of cached resources)."""
    a = load_prompt("outline")
    b = load_prompt("outline")
    assert a == b
