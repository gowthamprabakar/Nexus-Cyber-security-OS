"""Tests — ``data_security.scorer``.

Task 10. Stage 5 (SCORE) — correlation severity uplift:

- Findings with F.3 correlation get severity uplifted one level.
- Findings without correlation pass through unchanged.
- CRITICAL findings cap at CRITICAL on uplift.
- Severity-uplift order: INFO -> LOW -> MEDIUM -> HIGH -> CRITICAL.
- Uplift evidence is appended (existing evidence preserved).
- Empty inputs → empty output.
- Pure function (input findings not mutated).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from data_security.correlate import CorrelationResult
from data_security.detectors.public_bucket import detect_public_bucket
from data_security.detectors.unencrypted import detect_unencrypted
from data_security.schemas import ClassifierLabel, Severity
from data_security.scorer import apply_correlation_uplift
from data_security.tools.s3_inventory import (
    BucketAcl,
    BucketEncryption,
    BucketInventory,
    PublicAccessBlock,
)
from shared.fabric.envelope import NexusEnvelope


def _make_envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d5d5",
        tenant_id="acme",
        agent_id="data-security",
        nlah_version="d5-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _make_public_bucket(name: str = "alpha") -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(grants_all_users=["READ"]),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="AES256"),
    )


def _make_unencrypted_bucket(name: str = "alpha") -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="NONE"),
    )


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Uplift logic
# ---------------------------------------------------------------------------


def test_finding_without_correlation_passes_through_unchanged() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert findings[0].severity == Severity.HIGH

    correlation = CorrelationResult(matches={})
    out = apply_correlation_uplift(findings, correlation)
    assert len(out) == 1
    # Same object reference on no-op (defensive copy elision).
    assert out[0] is findings[0]
    assert out[0].severity == Severity.HIGH


def test_finding_with_correlation_uplifts_high_to_critical() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert findings[0].severity == Severity.HIGH

    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha"]})
    out = apply_correlation_uplift(findings, correlation)
    assert len(out) == 1
    assert out[0].severity == Severity.CRITICAL
    # New object — input was not mutated.
    assert out[0] is not findings[0]
    assert findings[0].severity == Severity.HIGH


def test_finding_with_correlation_uplifts_medium_to_high() -> None:
    """Unencrypted bucket → MEDIUM by default. Correlation uplifts to HIGH."""
    bucket = _make_unencrypted_bucket("alpha")
    findings = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert findings[0].severity == Severity.MEDIUM

    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha"]})
    out = apply_correlation_uplift(findings, correlation)
    assert out[0].severity == Severity.HIGH


def test_critical_caps_at_critical() -> None:
    """CRITICAL + correlation → still CRITICAL."""
    # Build a HIGH finding then uplift it once to CRITICAL, then once more.
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha"]})
    first_uplift = apply_correlation_uplift(findings, correlation)
    assert first_uplift[0].severity == Severity.CRITICAL

    # Re-apply: cap at CRITICAL.
    correlation_2 = CorrelationResult(
        matches={first_uplift[0].finding_id: ["CSPM-AWS-PROW-002-alpha"]}
    )
    second_uplift = apply_correlation_uplift(first_uplift, correlation_2)
    assert second_uplift[0].severity == Severity.CRITICAL


def test_critical_from_classifier_hit_caps_with_correlation() -> None:
    """Detector emitting CRITICAL (public + classifier hit) + correlation
    stays CRITICAL.
    """
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert findings[0].severity == Severity.CRITICAL

    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha"]})
    out = apply_correlation_uplift(findings, correlation)
    assert out[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Uplift order
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        (Severity.INFO, Severity.LOW),
        (Severity.LOW, Severity.MEDIUM),
        (Severity.MEDIUM, Severity.HIGH),
        (Severity.HIGH, Severity.CRITICAL),
        (Severity.CRITICAL, Severity.CRITICAL),
    ],
)
def test_uplift_order_is_one_level(base: Severity, expected: Severity) -> None:
    """Verify the documented one-level-up order with cap at CRITICAL.

    Uses the internal _UPLIFT table directly — the public scorer composes
    over this via apply_correlation_uplift.
    """
    from data_security.scorer import _UPLIFT

    assert _UPLIFT[base] == expected


# ---------------------------------------------------------------------------
# Evidence annotation
# ---------------------------------------------------------------------------


def test_uplift_appends_correlation_evidence() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    original_evidence_count = len(findings[0].to_dict()["evidences"])

    correlation = CorrelationResult(
        matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha", "CSPM-AWS-PROW-002-alpha"]}
    )
    out = apply_correlation_uplift(findings, correlation)

    payload = out[0].to_dict()
    evidences = payload["evidences"]
    assert len(evidences) == original_evidence_count + 1
    uplift_entry = evidences[-1]
    assert uplift_entry["rule"] == "correlation_uplift"
    assert uplift_entry["source"] == "f3_cloud_posture"
    assert uplift_entry["original_severity"] == "high"
    assert uplift_entry["uplifted_severity"] == "critical"
    assert uplift_entry["matched_f3_finding_ids"] == [
        "CSPM-AWS-PROW-001-alpha",
        "CSPM-AWS-PROW-002-alpha",
    ]


def test_uplift_preserves_original_evidence_fields() -> None:
    """Detector's evidence (e.g. ``acl_grants_all_users``) survives uplift."""
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)

    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001"]})
    out = apply_correlation_uplift(findings, correlation)

    detector_evidence = out[0].to_dict()["evidences"][0]
    assert detector_evidence["rule"] == "s3_bucket_public"
    assert detector_evidence["acl_grants_all_users"] == ["READ"]


def test_uplift_preserves_finding_id() -> None:
    """finding_id and rule_id are preserved — only severity + evidence change."""
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=3)
    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001"]})
    out = apply_correlation_uplift(findings, correlation)
    assert out[0].finding_id == findings[0].finding_id
    assert out[0].rule_id == findings[0].rule_id


def test_uplift_severity_id_round_trips() -> None:
    """OCSF severity_id must be updated alongside the severity string."""
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001"]})
    out = apply_correlation_uplift(findings, correlation)
    payload = out[0].to_dict()
    # CRITICAL → severity_id 5.
    assert payload["severity_id"] == 5
    assert payload["severity"] == "Critical"


# ---------------------------------------------------------------------------
# Pure function + immutability
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_output() -> None:
    correlation = CorrelationResult(matches={})
    assert apply_correlation_uplift([], correlation) == ()


def test_input_findings_not_mutated() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001"]})

    original_payload = findings[0].to_dict()
    apply_correlation_uplift(findings, correlation)
    after_payload = findings[0].to_dict()

    assert original_payload == after_payload
    assert findings[0].severity == Severity.HIGH


def test_scorer_no_module_state() -> None:
    from data_security import scorer as scorer_module

    snapshot_before = {k: id(v) for k, v in vars(scorer_module).items() if not k.startswith("__")}
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    correlation = CorrelationResult(matches={findings[0].finding_id: ["CSPM-AWS-PROW-001"]})
    for _ in range(10):
        apply_correlation_uplift(findings, correlation)
    snapshot_after = {k: id(v) for k, v in vars(scorer_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after


# ---------------------------------------------------------------------------
# Mixed input — some findings correlated, others not
# ---------------------------------------------------------------------------


def test_mixed_inputs_partial_uplift() -> None:
    """Multi-finding input: only correlated findings uplift; rest pass through."""
    bucket_a = _make_public_bucket("alpha")
    bucket_b = _make_public_bucket("beta")
    findings = detect_public_bucket(
        bucket_a, envelope=_make_envelope(), detected_at=_TS, sequence=1
    ) + detect_public_bucket(bucket_b, envelope=_make_envelope(), detected_at=_TS, sequence=2)
    assert len(findings) == 2
    correlation = CorrelationResult(
        matches={
            # Only alpha is correlated.
            findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha"],
        }
    )
    out = apply_correlation_uplift(findings, correlation)
    assert len(out) == 2
    assert out[0].severity == Severity.CRITICAL  # uplifted
    assert out[1].severity == Severity.HIGH  # unchanged
    # Beta untouched (object identity preserved).
    assert out[1] is findings[1]
