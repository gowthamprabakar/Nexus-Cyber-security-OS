"""investigation v0.2 Task 14 — categorical-only invariant tests (WI-I8, inherited from D.13)."""

from __future__ import annotations

import pytest
from investigation.privacy.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)


@pytest.mark.parametrize(
    "chunk",
    [
        "Hypothesis: the actor exfiltrated SSN 123-45-6789.",
        "Containment: rotate AKIAIOSFODNN7EXAMPLE immediately.",
        "Token eyJhbGc.eyJzdWI.sig in the audit log.",
        "Card 4111 1111 1111 1111 found at rest.",
    ],
)
def test_plaintext_pii_rejected(chunk: str) -> None:
    with pytest.raises(CategoricalContractViolationError, match="categorical-only"):
        assert_categorical_only(chunk)


@pytest.mark.parametrize(
    "chunk",
    [
        "Hypothesis: the actor accessed a store holding [SSN] and [CREDIT_CARD].",
        "Containment: rotate the exposed [AWS_ACCESS_KEY].",
        "No sensitive values were surfaced in this investigation.",
        "",
        "Timeline shows 3 audit events tied to finding `CSPM-1`.",
    ],
)
def test_categorical_labels_pass(chunk: str) -> None:
    assert_categorical_only(chunk)


def test_non_luhn_pan_passes() -> None:
    assert_categorical_only("Ticket reference 1234 5678 9012 3456 noted.")


def test_ssn_anywhere_rejected() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("Per the timeline, 123-45-6789 appeared at 02:00.")
