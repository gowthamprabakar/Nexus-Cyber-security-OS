"""Tests — `curiosity.prompts` (Task 5).

Validates:

1. The hypothesis template ships bundled and is loadable.
2. ``load_prompt`` accepts only the one valid name and raises on
   bad names.
3. Key instructional sections are present in the template (no
   template silently shipped empty / missing the Q6 reminder /
   missing the JSON-only constraint / missing the persona).

The hypothesis template is load-bearing for Task 6's hypothesizer
— if it ships malformed, the LLM will return garbage and every
eval case fails. The smoke layer here is the first line of
defence; eval case 05 (`q6_no_classifier_substring_in_hypothesis`)
is the second.
"""

from __future__ import annotations

import pytest
from curiosity.prompts import load_prompt


def test_load_hypothesis_returns_non_empty() -> None:
    text = load_prompt("hypothesis")
    assert text.strip()
    assert "Curiosity Agent" in text
    assert "Hypothesis Call" in text


def test_unknown_prompt_name_raises_value_error() -> None:
    with pytest.raises(ValueError, match="unknown prompt template"):
        load_prompt("bogus")


def test_load_prompt_idempotent_across_calls() -> None:
    """Calling load_prompt repeatedly returns identical text (no
    in-place mutation of cached resources)."""
    a = load_prompt("hypothesis")
    b = load_prompt("hypothesis")
    assert a == b


def test_hypothesis_template_carries_persona() -> None:
    text = load_prompt("hypothesis")
    assert "security exploration agent" in text.lower()


def test_hypothesis_template_documents_input_shape() -> None:
    """The LLM needs to know what coverage_gaps looks like."""
    text = load_prompt("hypothesis")
    assert "coverage_gaps" in text
    assert "region" in text
    assert "asset_count" in text
    assert "days_since_last_finding" in text
    assert "severity_hint" in text


def test_hypothesis_template_documents_output_schema() -> None:
    """The hypothesizer's JSON parser expects this exact shape."""
    text = load_prompt("hypothesis")
    assert "hypotheses" in text
    assert "statement" in text
    assert "rationale" in text
    assert "probe_directive" in text
    assert "cited_gap" in text


def test_hypothesis_template_documents_target_agent_enum() -> None:
    """The 3 valid target_agent values + 3 valid action values."""
    text = load_prompt("hypothesis")
    assert "investigation" in text
    assert "data_security" in text
    assert "threat_intel" in text
    assert "scan" in text
    assert "investigate" in text
    assert "enrich" in text


def test_hypothesis_template_documents_xor_constraint() -> None:
    """ProbeDirective requires exactly one of target_resource_arn /
    target_finding_id. The template must instruct the LLM."""
    text = load_prompt("hypothesis")
    assert "target_resource_arn" in text
    assert "target_finding_id" in text
    assert "XOR" in text or "exactly one" in text.lower()


def test_hypothesis_template_caps_count_at_five() -> None:
    """Per _MAX_HYPOTHESES_PER_RUN. Template MUST tell the LLM."""
    text = load_prompt("hypothesis")
    assert "5 hypotheses" in text or "Maximum 5" in text or "max 5" in text.lower()


def test_hypothesis_template_documents_statement_length() -> None:
    text = load_prompt("hypothesis")
    assert "400 chars" in text or "400 characters" in text


def test_hypothesis_template_documents_rationale_length() -> None:
    text = load_prompt("hypothesis")
    assert "1500 chars" in text or "1500 characters" in text


def test_hypothesis_template_carries_q6_reminder() -> None:
    """WI-2 acceptance — the template MUST instruct the LLM to never
    reproduce classifier-matched substrings (SSN values, credit-card
    numbers, AWS access keys, JWTs)."""
    text = load_prompt("hypothesis")
    assert "Q6" in text
    assert "SSN" in text
    assert "credit-card" in text.lower() or "credit card" in text.lower()
    assert "access key" in text.lower() or "access-key" in text.lower()
    assert "JWT" in text
    # The categorical-vs-value instruction
    assert "categorical" in text.lower() or "label" in text.lower()


def test_hypothesis_template_no_prose_instruction() -> None:
    """Like D.13's outline template, the hypothesizer JSON-parses
    the LLM output directly. The template must instruct JSON-only."""
    text = load_prompt("hypothesis")
    assert "JSON" in text
    # Several "no prose" phrasings acceptable
    assert (
        "No preamble" in text
        or "NO PROSE" in text
        or "only the JSON" in text.lower()
        or "only" in text.lower()
    )


def test_hypothesis_template_handles_empty_gaps_case() -> None:
    """The empty-gaps path returns `{"hypotheses": []}`. Template
    MUST document this so the LLM doesn't fabricate gaps."""
    text = load_prompt("hypothesis")
    assert "hypotheses" in text
    assert "[]" in text or "empty" in text.lower()
