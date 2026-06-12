"""curiosity v0.2 Task 12 — assert_categorical_only tests (WI-X9, inherited from D.13)."""

from __future__ import annotations

import pytest
from curiosity.privacy.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)


def test_categorical_label_passes() -> None:
    assert_categorical_only("Region eu-west-1 may have unscanned [SSN]-bearing workloads.")


def test_empty_passes() -> None:
    assert_categorical_only("")


def test_plaintext_ssn_raises() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("subject SSN 123-45-6789 was seen")


def test_aws_key_raises() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("key AKIAIOSFODNN7EXAMPLE leaked")


def test_jwt_raises() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("token eyJhbGciOi.eyJzdWIiOi.abc123")


def test_luhn_pan_raises() -> None:
    with pytest.raises(CategoricalContractViolationError):
        assert_categorical_only("card 4111 1111 1111 1111 on file")


def test_non_luhn_digits_pass() -> None:
    # A 16-digit string failing Luhn is not flagged as a PAN.
    assert_categorical_only("ticket 1234 5678 9012 3456 reference")
