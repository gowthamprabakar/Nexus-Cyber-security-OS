"""synthesis v0.2 Task 15 — categorical-only narrative invariant tests (WI-Y8/Q4)."""

from __future__ import annotations

import pytest
from synthesis.privacy.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)


@pytest.mark.parametrize(
    "chunk",
    [
        "The user SSN 123-45-6789 was exposed.",
        "Key AKIAIOSFODNN7EXAMPLE found in the bucket.",
        "Token eyJhbGc.eyJzdWI.sig leaked.",
        "Card 4111 1111 1111 1111 in plaintext.",
    ],
)
def test_plaintext_pii_rejected(chunk: str) -> None:
    with pytest.raises(CategoricalContractViolationError, match="categorical-only"):
        assert_categorical_only(chunk)


@pytest.mark.parametrize(
    "chunk",
    [
        "One [SSN] and two [CREDIT_CARD] values were found in S3.",
        "data-security flagged 3 [AWS_ACCESS_KEY] exposures.",
        "No sensitive data was detected this scan window.",
        "",
        "compliance reported 5 failing controls across the fleet.",
    ],
)
def test_categorical_labels_pass(chunk: str) -> None:
    assert_categorical_only(chunk)  # does not raise


def test_non_luhn_pan_shape_passes() -> None:
    # A 16-digit-shaped number that fails Luhn is not a real PAN -> allowed.
    assert_categorical_only("Reference number 1234 5678 9012 3456 in the ticket.")


def test_ssn_anywhere_in_text_rejected() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("Per finding CSPM-1, the value 123-45-6789 appeared.")


def test_clean_multiline_passes() -> None:
    assert_categorical_only("## Posture\n\nThe fleet has 12 [SSN] findings.\n\nReview advised.")
