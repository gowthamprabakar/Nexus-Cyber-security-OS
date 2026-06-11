"""data-security v0.2 Task 10 — confidence scoring + privacy-hash emission tests (WI-S8/S9)."""

from __future__ import annotations

from data_security.classifiers.scored import ScoredClassification, classify_scored
from data_security.privacy import assert_privacy_contract, privacy_hash
from data_security.schemas import ClassifierLabel


def test_unambiguous_high_confidence() -> None:
    sc = classify_scored("AKIAIOSFODNN7EXAMPLE")
    assert sc.label == ClassifierLabel.AWS_ACCESS_KEY and sc.confidence == 1.0


def test_luhn_validated_confidence() -> None:
    sc = classify_scored("123-45-6789")
    assert sc.label == ClassifierLabel.SSN and sc.confidence == 0.95


def test_context_required_confidence() -> None:
    sc = classify_scored("CVV: 123")
    assert sc.label == ClassifierLabel.CVV and sc.confidence == 0.8


def test_none_zero_confidence() -> None:
    sc = classify_scored("ordinary text")
    assert sc.label == ClassifierLabel.NONE and sc.confidence == 0.0
    assert sc.is_sensitive is False


def test_privacy_hash_present_and_correct() -> None:
    sc = classify_scored("123-45-6789")
    assert sc.content_hash == privacy_hash("123-45-6789")
    assert len(sc.content_hash) == 64


def test_scored_carries_no_content() -> None:
    # WI-S8/S9: ScoredClassification holds label + confidence + hash only — no content field.
    fields = set(ScoredClassification.__slots__)
    assert fields == {"label", "confidence", "content_hash"}
    assert not any(f == "content" or "text" in f or "sample" in f for f in fields)


def test_to_evidence_is_privacy_safe() -> None:
    ev = classify_scored("patient SSN 123-45-6789").to_evidence()
    assert ev["classification_label"] == "ssn"
    assert "privacy_hash" in ev and "confidence" in ev
    # The evidence carries no plaintext sensitive content -> passes the privacy contract.
    assert_privacy_contract(ev)


def test_to_evidence_for_pci() -> None:
    ev = classify_scored("CVV 999").to_evidence()
    assert ev["classification_label"] == "cvv"
    assert_privacy_contract(ev)  # label + hash only -> no leak
