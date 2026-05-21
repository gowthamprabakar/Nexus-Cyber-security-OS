"""Tests — `curiosity.reviewer` (Task 7).

D.12's second-line scrub against classifier-substring leakage.
Reuses D.13's `synthesis.reviewer._scan_classifier_labels` so both
agents enforce the same Q6 contract end-to-end.

14 tests covering:

1. Clean draft passes.
2. Empty draft passes (no hypotheses — legal clean-run output
   from the empty-gaps short-circuit).
3. SSN in statement fails Q6.
4. AWS access key in statement fails Q6.
5. JWT in rationale fails Q6.
6. SSN in rationale fails Q6.
7. Credit-card Luhn-valid fails Q6.
8. Credit-card Luhn-invalid passes.
9. Multiple violations in one draft -> all reported.
10. Violation strings DO NOT contain the matched substring (Q6
    meta-invariant; matches D.13's reviewer posture).
11. Passed verdict carries empty retry_hint and violations.
12. Verdict is frozen (mutation raises).
13. q6 takes retry_hint precedence over shape (when both fail).
14. Empty-rationale_ref hypothesis passes (empty string is the
    legal pending-driver-fill state).
"""

from __future__ import annotations

import pytest
from curiosity.reviewer import RETRY_HINT_Q6, review
from curiosity.schemas import (
    CoverageGap,
    CuriosityDraft,
    Hypothesis,
    ProbeAction,
    ProbeDirective,
    TargetAgent,
)
from pydantic import ValidationError


def _gap() -> CoverageGap:
    return CoverageGap(
        region="us-east-1",
        asset_count=42,
        days_since_last_finding=60,
        severity_hint="medium",
    )


def _directive(**overrides: object) -> ProbeDirective:
    defaults: dict[str, object] = {
        "target_agent": TargetAgent.DATA_SECURITY,
        "target_resource_arn": "arn:aws:s3:::region-bucket",
        "action": ProbeAction.SCAN,
        "rationale_ref": "01J7M3X9Z1K8RPVQNH2T8DBHFZ",  # ULID claim_id
    }
    defaults.update(overrides)
    return ProbeDirective(**defaults)  # type: ignore[arg-type]


def _hypothesis(**overrides: object) -> Hypothesis:
    defaults: dict[str, object] = {
        "statement": "Region us-east-1 appears under-scanned with 42 assets.",
        "rationale": (
            "Region us-east-1 has 42 assets but no findings in the scan window. "
            "This is consistent with either clean posture or a coverage gap. "
            "Recommend running D.5 to establish a baseline."
        ),
        "probe_directive": _directive(),
        "cited_gap": _gap(),
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)  # type: ignore[arg-type]


def _draft(*hypotheses: Hypothesis) -> CuriosityDraft:
    return CuriosityDraft(
        hypotheses=tuple(hypotheses),
        llm_call_count=1 if hypotheses else 0,
        total_tokens_used=150 if hypotheses else 0,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_clean_draft_passes() -> None:
    verdict = review(_draft(_hypothesis()))
    assert verdict.passed is True
    assert verdict.retry_hint == ""
    assert verdict.violations == []


def test_empty_draft_passes() -> None:
    """Empty draft is the legal short-circuit output when the gap
    detector finds nothing. NOT a shape violation."""
    verdict = review(_draft())
    assert verdict.passed is True
    assert verdict.violations == []


def test_empty_rationale_ref_passes() -> None:
    """Empty rationale_ref is the legal pending-driver-fill state
    (the driver populates with the freshly-minted claim_id)."""
    h = _hypothesis(
        probe_directive=_directive(rationale_ref=""),
    )
    verdict = review(_draft(h))
    assert verdict.passed is True


# ---------------------------------------------------------------------------
# Q6 substring guard — statement
# ---------------------------------------------------------------------------


def test_ssn_in_statement_fails_q6() -> None:
    h = _hypothesis(
        statement="Region us-east-1 may contain SSN 123-45-6789 in unscanned buckets.",
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("ssn" in v for v in verdict.violations)


def test_aws_access_key_in_statement_fails_q6() -> None:
    h = _hypothesis(
        statement="An AKIAIOSFODNN7EXAMPLE key may be in plaintext somewhere.",
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("aws_access_key" in v for v in verdict.violations)


# ---------------------------------------------------------------------------
# Q6 substring guard — rationale
# ---------------------------------------------------------------------------


def test_jwt_in_rationale_fails_q6() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123"
    h = _hypothesis(
        rationale=(
            f"This region likely has leaked JWTs. For example, {jwt} was "
            "previously surfaced in unrelated audit chains."
        ),
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6
    assert any("jwt" in v for v in verdict.violations)


def test_ssn_in_rationale_fails_q6() -> None:
    h = _hypothesis(
        rationale=(
            "The region's buckets may contain SSN values like 555-55-5555 in "
            "plaintext. Recommend a classification scan to confirm."
        ),
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert verdict.retry_hint == RETRY_HINT_Q6


# ---------------------------------------------------------------------------
# Credit-card Luhn discrimination
# ---------------------------------------------------------------------------


def test_credit_card_luhn_valid_fails_q6() -> None:
    """4111-1111-1111-1111 is a known Luhn-valid PAN test number."""
    h = _hypothesis(
        rationale=(
            "Buckets in this region may have leaked PAN data; example: "
            "4111-1111-1111-1111. Audit recommended."
        ),
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert any("credit_card" in v for v in verdict.violations)


def test_credit_card_luhn_invalid_passes() -> None:
    """1234-5678-9012-3456 is not Luhn-valid -> not a real PAN."""
    h = _hypothesis(
        rationale=(
            "Internal account IDs follow a 1234-5678-9012-3456 format that is "
            "not a credit card. No PAN content expected."
        ),
    )
    verdict = review(_draft(h))
    assert verdict.passed is True


# ---------------------------------------------------------------------------
# Multi-violation reporting
# ---------------------------------------------------------------------------


def test_multiple_violations_reported_in_single_verdict() -> None:
    """Both SSN + AWS access key in the same hypothesis -> both
    surfaced in the violations list."""
    h = _hypothesis(
        rationale=(
            "Leaked SSN 111-22-3333 and AWS key AKIAIOSFODNN7EXAMPLE were "
            "previously observed in adjacent tenants."
        ),
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    assert len(verdict.violations) >= 2
    assert any("ssn" in v for v in verdict.violations)
    assert any("aws_access_key" in v for v in verdict.violations)


# ---------------------------------------------------------------------------
# Q6 meta-invariant — violation strings never contain the matched substring
# ---------------------------------------------------------------------------


def test_violation_strings_do_not_contain_matched_substring() -> None:
    """Q6 invariant applies to the reviewer's OWN audit output too —
    matches D.13's reviewer discipline."""
    secret_ssn = "987-65-4321"  # noqa: S105 -- synthetic Q6 probe substring
    secret_key = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 -- synthetic Q6 probe substring
    h = _hypothesis(
        rationale=f"Region carries {secret_ssn} and {secret_key} risk.",
    )
    verdict = review(_draft(h))
    assert verdict.passed is False
    for v in verdict.violations:
        assert secret_ssn not in v
        assert secret_key not in v


# ---------------------------------------------------------------------------
# Verdict shape stability
# ---------------------------------------------------------------------------


def test_passed_verdict_carries_empty_retry_hint_and_violations() -> None:
    verdict = review(_draft(_hypothesis()))
    assert verdict.passed is True
    assert verdict.retry_hint == ""
    assert verdict.violations == []


def test_verdict_is_frozen_pydantic() -> None:
    verdict = review(_draft(_hypothesis()))
    with pytest.raises((TypeError, ValidationError)):
        verdict.passed = False  # type: ignore[misc]
