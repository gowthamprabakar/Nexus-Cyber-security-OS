"""data-security v0.2 Task 8 — PHI taxonomy classifier tests (HIPAA-aligned, label-only)."""

from __future__ import annotations

from data_security.classifiers.patterns import _npi_valid, classify
from data_security.schemas import ClassifierLabel


def test_mrn_with_context() -> None:
    assert classify("Patient MRN: A1234567") == ClassifierLabel.MEDICAL_RECORD_NUMBER
    assert classify("medical record number 998877") == ClassifierLabel.MEDICAL_RECORD_NUMBER


def test_mrn_requires_context() -> None:
    # A bare alphanumeric without MRN context is not flagged as MRN.
    assert classify("the value A1234567 appears here") == ClassifierLabel.NONE


def test_icd10_dotted_code() -> None:
    assert classify("diagnosis E11.9 noted") == ClassifierLabel.ICD10_CODE
    assert classify("J45.909") == ClassifierLabel.ICD10_CODE


def test_npi_valid_luhn() -> None:
    assert _npi_valid("1234567893") is True
    assert classify("Provider NPI 1234567893") == ClassifierLabel.NPI


def test_npi_invalid_luhn_not_flagged() -> None:
    assert _npi_valid("1234567890") is False
    assert classify("NPI 1234567890") == ClassifierLabel.NONE


def test_npi_requires_context() -> None:
    # A bare 10-digit number (even Luhn-valid) without NPI context isn't flagged.
    assert classify("order 1234567893 shipped") == ClassifierLabel.NONE


# --- byte-identical precedence: v0.1 labels unchanged ---


def test_v01_ssn_still_first() -> None:
    assert classify("ssn 123-45-6789") == ClassifierLabel.SSN


def test_v01_credit_card_still_works() -> None:
    assert classify("card 4111 1111 1111 1111") == ClassifierLabel.CREDIT_CARD


def test_clean_text_is_none() -> None:
    assert classify("a perfectly ordinary sentence") == ClassifierLabel.NONE
