"""Tests — ``synthesis.reviewer`` (Task 7).

The reviewer is D.13's second-line scrub against classifier-substring
leakage (the first line is Stage 2 ENRICH's structured-fields-only
context bundle). These tests cover both layers:

1. Shape checks — section count, headings, body, executive summary.
2. Q6 substring guard — SSN / credit-card (Luhn) / AWS access key /
   JWT patterns over the rendered narrative + exec-summary paragraph.

WI-2 acceptance gate: Q6 violations always reject with
``retry_hint=q6_violation`` so the narrator can re-run with the
``q6_violation_retry_hint=True`` banner injected.
"""

from __future__ import annotations

from synthesis.narrator import SynthesisDraft
from synthesis.reviewer import RETRY_HINT_Q6, RETRY_HINT_SHAPE, review
from synthesis.schemas import (
    ExecutiveSummary,
    NarrativeSection,
    OutlineSection,
    SynthesisOutline,
)


def _outline(sections: int = 1) -> SynthesisOutline:
    return SynthesisOutline(
        sections=[
            OutlineSection(
                heading=f"Section {i + 1}",
                intent=f"Intent {i + 1}",
                cited_finding_ids=[f"CSPM-{i + 1:03d}"],
            )
            for i in range(sections)
        ],
        overall_narrative_intent="Cover the findings.",
    )


def _draft(
    *,
    sections: list[NarrativeSection] | None = None,
    exec_paragraph: str = "Clean executive summary.",
) -> SynthesisDraft:
    if sections is None:
        sections = [
            NarrativeSection(
                heading="Section 1",
                body="Clean body referencing finding `CSPM-001`.",
                cited_finding_ids=["CSPM-001"],
            )
        ]
    return SynthesisDraft(
        outline=_outline(len(sections) if sections else 1),
        sections=tuple(sections),
        executive_summary=ExecutiveSummary(
            paragraph=exec_paragraph, key_metrics={"total_findings": 1}
        ),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_clean_draft_passes() -> None:
    verdict = review(_draft())
    assert verdict.passed is True
    assert verdict.retry_hint == ""
    assert verdict.violations == []


def test_placeholder_body_passes_shape_check() -> None:
    """Per-section narration failure -> ``[section narration unavailable]``
    placeholder. That's degraded but legal output; reviewer passes it."""
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Section 1",
                body="[section narration unavailable]",
                cited_finding_ids=["CSPM-001"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is True


# ---------------------------------------------------------------------------
# Layer 1 — shape checks
# ---------------------------------------------------------------------------


def test_zero_sections_fails_shape() -> None:
    """No sections at all -> shape violation. Note SynthesisOutline
    requires >=1 section; we use the draft directly to bypass that."""
    draft = SynthesisDraft(
        outline=_outline(1),
        sections=(),
        executive_summary=ExecutiveSummary(paragraph="Summary.", key_metrics={"total_findings": 0}),
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_SHAPE
    assert any("zero sections" in v for v in verdict.violations)


def test_whitespace_only_body_fails_shape() -> None:
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Section 1",
                body="   \n\t  ",
                cited_finding_ids=[],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_SHAPE
    assert any("empty body" in v for v in verdict.violations)


def test_empty_executive_summary_paragraph_fails_shape() -> None:
    draft = _draft(exec_paragraph="   ")
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_SHAPE
    assert any("executive_summary" in v for v in verdict.violations)


# ---------------------------------------------------------------------------
# Layer 2 — Q6 substring guard
# ---------------------------------------------------------------------------


def test_ssn_substring_in_body_fails_q6() -> None:
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Identity",
                body="The bucket was found to contain 123-45-6789 which is a US SSN.",
                cited_finding_ids=["CSPM-IAM-1"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("ssn" in v for v in verdict.violations)


def test_aws_access_key_in_body_fails_q6() -> None:
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="IAM",
                body="The leaked key was AKIAIOSFODNN7EXAMPLE in plaintext.",
                cited_finding_ids=["CSPM-IAM-2"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("aws_access_key" in v for v in verdict.violations)


def test_jwt_substring_in_body_fails_q6() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123"
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Tokens",
                body=f"A leaked JWT was found: {jwt}",
                cited_finding_ids=["CSPM-IAM-3"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("jwt" in v for v in verdict.violations)


def test_credit_card_luhn_valid_fails_q6() -> None:
    """4111-1111-1111-1111 is a well-known Luhn-valid test PAN."""
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Payments",
                body="The exposed card was 4111-1111-1111-1111 in the bucket.",
                cited_finding_ids=["CSPM-DS-1"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("credit_card" in v for v in verdict.violations)


def test_credit_card_luhn_invalid_passes() -> None:
    """1234-5678-9012-3456 is NOT Luhn-valid -> not a real PAN."""
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Account refs",
                body="Internal account ID 1234-5678-9012-3456 was logged.",
                cited_finding_ids=["CSPM-FIN-1"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is True


def test_ssn_in_executive_summary_fails_q6() -> None:
    """Plan §Q6: 'the executive summary is the highest-visibility output
    — matched-substring leakage here is the worst-case Q6 failure'."""
    draft = _draft(
        exec_paragraph="One bucket contained the SSN 555-55-5555 in plaintext.",
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("executive_summary" in v and "ssn" in v for v in verdict.violations)


def test_multiple_violations_reported_in_single_verdict() -> None:
    """All violations should surface so the audit log captures them."""
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Section 1",
                body="SSN 111-22-3333 and AKIAIOSFODNN7EXAMPLE both leaked.",
                cited_finding_ids=["CSPM-1"],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert len(verdict.violations) >= 2
    assert any("ssn" in v for v in verdict.violations)
    assert any("aws_access_key" in v for v in verdict.violations)


# ---------------------------------------------------------------------------
# Precedence — Q6 wins over shape when both fail
# ---------------------------------------------------------------------------


def test_q6_violation_takes_retry_hint_precedence_over_shape() -> None:
    """If both shape AND Q6 fail, retry_hint is q6_violation (cheaper retry)."""
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Section 1",
                body="123-45-6789 — only the SSN, no other prose.",
                cited_finding_ids=[],
            )
        ],
        exec_paragraph="   ",  # whitespace-only -- shape violation
    )
    verdict = review(draft)
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    # Both kinds of violations are surfaced.
    assert any("ssn" in v for v in verdict.violations)
    assert any("executive_summary" in v for v in verdict.violations)


# ---------------------------------------------------------------------------
# Violation strings never leak the matched substring
# ---------------------------------------------------------------------------


def test_violation_strings_do_not_contain_the_matched_substring() -> None:
    """Q6 invariant applies to the reviewer's OWN audit output too —
    the violation list names labels, never the matched substrings."""
    secret_ssn = "987-65-4321"  # noqa: S105 -- synthetic Q6 probe substring
    secret_key = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 -- synthetic Q6 probe substring
    draft = _draft(
        sections=[
            NarrativeSection(
                heading="Section 1",
                body=f"{secret_ssn} and {secret_key} both leaked.",
                cited_finding_ids=[],
            )
        ]
    )
    verdict = review(draft)
    assert verdict.passed is False
    for v in verdict.violations:
        assert secret_ssn not in v
        assert secret_key not in v


# ---------------------------------------------------------------------------
# ReviewVerdict shape stability
# ---------------------------------------------------------------------------


def test_passed_verdict_carries_empty_retry_hint_and_violations() -> None:
    """Plan: passed=True -> retry_hint=='' and violations==[]."""
    verdict = review(_draft())
    assert verdict.passed is True
    assert verdict.retry_hint == ""
    assert verdict.violations == []


def test_verdict_is_frozen_pydantic() -> None:
    """ReviewVerdict has frozen=True; mutation attempts raise."""
    import pytest
    from pydantic import ValidationError

    verdict = review(_draft())
    with pytest.raises((TypeError, ValidationError)):
        verdict.passed = False  # type: ignore[misc]
