"""data-security v0.2 Task 9 — PCI-DSS classifier expansion tests (label-only)."""

from __future__ import annotations

from data_security.classifiers.patterns import classify
from data_security.schemas import ClassifierLabel


def test_cvv_with_context() -> None:
    assert classify("CVV: 123") == ClassifierLabel.CVV
    assert classify("card verification value 4321") == ClassifierLabel.CVV


def test_cvv_requires_context() -> None:
    # A bare 3-digit number is not a CVV.
    assert classify("room 123 on floor 4") == ClassifierLabel.NONE


def test_card_expiration() -> None:
    assert classify("exp 09/27") == ClassifierLabel.CARD_EXPIRATION
    assert classify("valid thru 12/2029") == ClassifierLabel.CARD_EXPIRATION


def test_card_expiration_requires_context() -> None:
    assert classify("the ratio is 09/27 today") == ClassifierLabel.NONE


def test_track_data_track1() -> None:
    # Track 1 sentinels with a non-Luhn PAN (so it reaches TRACK_DATA, not CREDIT_CARD).
    assert classify("%B4111111111111112^DOE/JANE^2709...") == ClassifierLabel.TRACK_DATA


def test_track_data_track2() -> None:
    assert classify(";4111111111111112=27091010000012300000?") == ClassifierLabel.TRACK_DATA


# --- byte-identical precedence: v0.1 + Task-8 labels unchanged ---


def test_valid_pan_still_credit_card() -> None:
    # A valid-Luhn PAN dominates (CREDIT_CARD precedence is above PCI additions).
    assert classify("4111 1111 1111 1111") == ClassifierLabel.CREDIT_CARD


def test_ssn_still_first() -> None:
    assert classify("123-45-6789") == ClassifierLabel.SSN


def test_phi_npi_still_works() -> None:
    assert classify("NPI 1234567893") == ClassifierLabel.NPI


def test_clean_text_none() -> None:
    assert classify("nothing sensitive here") == ClassifierLabel.NONE
