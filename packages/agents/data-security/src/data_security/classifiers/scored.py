"""Classification confidence scoring + privacy-hash emission (data-security v0.2 Task 10).

Wraps the label-only `classify` with a per-label **confidence** + the **privacy hash** of the
content (WI-S9), producing a `ScoredClassification` that carries **label + confidence + hash
ONLY** — never the content (WI-S8). Its `to_evidence()` is the privacy-safe payload a finding
may carry, and it passes `assert_privacy_contract` by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from data_security.classifiers.patterns import classify
from data_security.privacy import privacy_hash
from data_security.schemas import ClassifierLabel

# Per-label detection confidence: unambiguous prefixes/sentinels = 1.0; check-digit-validated
# = 0.95; context-required = 0.8; format-only PII = 0.7; permissive catch-alls lower.
_CONFIDENCE: dict[ClassifierLabel, float] = {
    ClassifierLabel.AWS_ACCESS_KEY: 1.0,
    ClassifierLabel.JWT: 1.0,
    ClassifierLabel.TRACK_DATA: 1.0,
    ClassifierLabel.SSN: 0.95,
    ClassifierLabel.CREDIT_CARD: 0.95,
    ClassifierLabel.NPI: 0.95,
    ClassifierLabel.MEDICAL_RECORD_NUMBER: 0.8,
    ClassifierLabel.CVV: 0.8,
    ClassifierLabel.CARD_EXPIRATION: 0.8,
    ClassifierLabel.ICD10_CODE: 0.75,
    ClassifierLabel.EMAIL: 0.7,
    ClassifierLabel.PHONE: 0.7,
    ClassifierLabel.GENERIC_API_TOKEN: 0.6,
    ClassifierLabel.NONE: 0.0,
}


@dataclass(frozen=True, slots=True)
class ScoredClassification:
    label: ClassifierLabel
    confidence: float
    content_hash: str  # SHA-256 of the content — NOT the content (WI-S9)

    @property
    def is_sensitive(self) -> bool:
        return self.label is not ClassifierLabel.NONE

    def to_evidence(self) -> dict[str, Any]:
        """The privacy-safe evidence payload — label + confidence + hash, never content."""
        return {
            "classification_label": self.label.value,
            "confidence": self.confidence,
            "privacy_hash": self.content_hash,
        }


def classify_scored(text: str) -> ScoredClassification:
    """Classify ``text`` → label + confidence + privacy hash (content is never retained)."""
    label = classify(text)
    return ScoredClassification(
        label=label,
        confidence=_CONFIDENCE[label],
        content_hash=privacy_hash(text),
    )
