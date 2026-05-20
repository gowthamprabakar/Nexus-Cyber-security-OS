"""Tests — ``data_security.summarizer``.

Task 11. Stage 6 (SUMMARIZE). Covers:

- Empty findings → "No findings" placeholder.
- Header carries run_id + total + per-severity counts.
- Per-detector breakdown sorted alphabetically by rule.
- CRITICAL pinned above HIGH, MEDIUM below.
- Findings sorted deterministically by finding_id within a section.
- Classifier-label tokens surface in the report (label only, NEVER
  matched text — Q6 invariant).
- F.3 correlation finding-ids surface for uplifted findings.
- **Q6 RENDER-LAYER ASSERT** — if a finding's evidence contains a
  PII pattern (e.g. matched_text leaked into evidence), the
  summarizer raises SummarizerQ6Violation.
- Deterministic: same input → same output.
- Pure function: no module state mutation.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from data_security.correlate import CorrelationResult
from data_security.detectors.public_bucket import detect_public_bucket
from data_security.detectors.unencrypted import detect_unencrypted
from data_security.schemas import ClassifierLabel, CloudPostureFinding
from data_security.scorer import apply_correlation_uplift
from data_security.summarizer import (
    SummarizerQ6Violation,
    render_summary,
)
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


def _make_public_bucket(name: str) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(grants_all_users=["READ"]),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="AES256"),
    )


def _make_unencrypted_bucket(name: str) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="NONE"),
    )


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)
_RUN_ID = "00000000-d5d5-d5d5-d5d5-000000000005"


# ---------------------------------------------------------------------------
# Empty + header
# ---------------------------------------------------------------------------


def test_empty_findings_renders_no_findings_placeholder() -> None:
    out = render_summary([], run_id=_RUN_ID)
    assert "No findings emitted." in out
    assert "Data Security Agent (D.5)" in out
    assert _RUN_ID in out


def test_header_contains_run_id_and_total() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    out = render_summary(findings, run_id=_RUN_ID)
    assert f"**run_id**: `{_RUN_ID}`" in out
    assert "**total_findings**: 1" in out


def test_header_includes_all_severity_counts() -> None:
    out = render_summary([], run_id=_RUN_ID)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert f"**{sev}**: 0" in out


# ---------------------------------------------------------------------------
# Per-detector breakdown
# ---------------------------------------------------------------------------


def test_per_detector_breakdown_lists_rules() -> None:
    bucket_a = _make_public_bucket("alpha")
    bucket_b = _make_unencrypted_bucket("beta")
    findings = detect_public_bucket(
        bucket_a, envelope=_make_envelope(), detected_at=_TS, sequence=1
    ) + detect_unencrypted(bucket_b, envelope=_make_envelope(), detected_at=_TS, sequence=2)
    out = render_summary(findings, run_id=_RUN_ID)
    assert "`s3_bucket_public`: 1" in out
    assert "`s3_bucket_unencrypted`: 1" in out


def test_per_detector_breakdown_alphabetical() -> None:
    """Rule list is alphabetical (stable ordering for visual diff)."""
    bucket_a = _make_public_bucket("alpha")
    bucket_b = _make_unencrypted_bucket("beta")
    findings = detect_public_bucket(
        bucket_a, envelope=_make_envelope(), detected_at=_TS, sequence=1
    ) + detect_unencrypted(bucket_b, envelope=_make_envelope(), detected_at=_TS, sequence=2)
    out = render_summary(findings, run_id=_RUN_ID)
    # s3_bucket_public comes before s3_bucket_unencrypted alphabetically.
    pos_public = out.index("`s3_bucket_public`:")
    pos_unenc = out.index("`s3_bucket_unencrypted`:")
    assert pos_public < pos_unenc


# ---------------------------------------------------------------------------
# Severity section ordering
# ---------------------------------------------------------------------------


def test_critical_section_pinned_above_high() -> None:
    """CRITICAL appears before HIGH in the rendered output."""
    bucket_a = _make_public_bucket("alpha")  # HIGH
    bucket_b = _make_public_bucket("beta")  # CRITICAL via classifier hit
    findings = detect_public_bucket(
        bucket_a, envelope=_make_envelope(), detected_at=_TS, sequence=1
    ) + detect_public_bucket(
        bucket_b,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
        sequence=2,
    )
    out = render_summary(findings, run_id=_RUN_ID)
    pos_critical = out.index("## CRITICAL")
    pos_high = out.index("## HIGH")
    assert pos_critical < pos_high


def test_only_present_severities_have_sections() -> None:
    """No HIGH findings → no HIGH section."""
    bucket = _make_unencrypted_bucket("alpha")  # MEDIUM
    findings = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    out = render_summary(findings, run_id=_RUN_ID)
    assert "## MEDIUM" in out
    assert "## HIGH" not in out  # No HIGH findings
    assert "## CRITICAL" not in out


def test_findings_sorted_by_finding_id_within_section() -> None:
    """Findings inside a severity section are sorted alphabetically by finding_id.

    The finding-id format is CSPM-AWS-PUBLIC-NNN-<slug>; with same prefix and
    same sequence number, the bucket-name slug drives sort order.
    """
    bucket_a = _make_public_bucket("zebra")
    bucket_b = _make_public_bucket("alpha")
    findings = detect_public_bucket(
        bucket_a, envelope=_make_envelope(), detected_at=_TS, sequence=1
    ) + detect_public_bucket(bucket_b, envelope=_make_envelope(), detected_at=_TS, sequence=1)
    out = render_summary(findings, run_id=_RUN_ID)
    # Same sequence (001), different slugs → slug drives sort:
    # CSPM-AWS-PUBLIC-001-alpha sorts before CSPM-AWS-PUBLIC-001-zebra.
    pos_alpha = out.index("CSPM-AWS-PUBLIC-001-alpha")
    pos_zebra = out.index("CSPM-AWS-PUBLIC-001-zebra")
    assert pos_alpha < pos_zebra


# ---------------------------------------------------------------------------
# Classifier labels + correlation surface in the report
# ---------------------------------------------------------------------------


def test_classifier_labels_surface_as_tokens() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN, ClassifierLabel.CREDIT_CARD],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    out = render_summary(findings, run_id=_RUN_ID)
    # Both labels surface as tokens.
    assert "`ssn`" in out
    assert "`credit_card`" in out


def test_finding_without_classifier_hits_renders_none() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    out = render_summary(findings, run_id=_RUN_ID)
    assert "**classifier labels**: (none)" in out


def test_correlation_ids_surface_for_uplifted_findings() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    correlation = CorrelationResult(
        matches={findings[0].finding_id: ["CSPM-AWS-PROW-001-alpha", "CSPM-AWS-PROW-002-alpha"]}
    )
    scored = apply_correlation_uplift(findings, correlation)
    out = render_summary(scored, run_id=_RUN_ID)
    assert "**F.3 correlation**:" in out
    assert "`CSPM-AWS-PROW-001-alpha`" in out
    assert "`CSPM-AWS-PROW-002-alpha`" in out
    assert "(severity uplifted)" in out


def test_uncorrelated_finding_omits_correlation_line() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    out = render_summary(findings, run_id=_RUN_ID)
    assert "**F.3 correlation**:" not in out


# ---------------------------------------------------------------------------
# Q6 RENDER-LAYER ASSERT — LOAD-BEARING
# ---------------------------------------------------------------------------


def test_q6_clean_render_does_not_raise() -> None:
    """The standard render path produces no classifier hits."""
    bucket = _make_public_bucket("corp-data-lake")
    findings = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN, ClassifierLabel.CREDIT_CARD],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    # Should NOT raise — label tokens like "ssn" / "credit_card" are
    # not classifier patterns themselves.
    render_summary(findings, run_id=_RUN_ID)


def test_q6_violation_raised_if_finding_evidence_leaks_pii() -> None:
    """If a finding's payload somehow contains a PII pattern (e.g. through
    a future regression that adds matched_text to evidence), the
    summarizer's render-layer assert MUST raise.
    """
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    # Forge a leaky payload: set the finding's title to include a real
    # SSN pattern. This simulates a future regression where matched
    # content escapes into a finding field.
    payload = findings[0].to_dict()
    payload["finding_info"]["title"] = "Bucket alpha containing SSN 123-45-6789"
    leaky_finding = CloudPostureFinding(payload)

    with pytest.raises(SummarizerQ6Violation, match="ssn"):
        render_summary([leaky_finding], run_id=_RUN_ID)


def test_q6_violation_message_mentions_label() -> None:
    """The violation message names the label found (helps debugging).

    Leak via title (which IS rendered) — desc isn't currently in the
    rendered output, so this test pins the title field to verify the
    label-specific assert path.
    """
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    payload = findings[0].to_dict()
    payload["finding_info"]["title"] = "leak: alice@example.com"
    leaky_finding = CloudPostureFinding(payload)
    with pytest.raises(SummarizerQ6Violation) as ex:
        render_summary([leaky_finding], run_id=_RUN_ID)
    assert "email" in str(ex.value)


# ---------------------------------------------------------------------------
# Determinism + purity
# ---------------------------------------------------------------------------


def test_render_is_deterministic() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    out1 = render_summary(findings, run_id=_RUN_ID)
    out2 = render_summary(findings, run_id=_RUN_ID)
    assert out1 == out2


def test_summarizer_no_module_state() -> None:
    from data_security import summarizer as sum_module

    snapshot_before = {k: id(v) for k, v in vars(sum_module).items() if not k.startswith("__")}
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    for _ in range(10):
        render_summary(findings, run_id=_RUN_ID)
    snapshot_after = {k: id(v) for k, v in vars(sum_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after


# ---------------------------------------------------------------------------
# Output shape — markdown well-formed
# ---------------------------------------------------------------------------


def test_output_ends_with_newline() -> None:
    out = render_summary([], run_id=_RUN_ID)
    assert out.endswith("\n")


def test_output_contains_h1_title() -> None:
    out = render_summary([], run_id=_RUN_ID)
    assert out.startswith("# Data Security Agent")


def test_finding_arn_appears_in_section() -> None:
    bucket = _make_public_bucket("alpha")
    findings = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    out = render_summary(findings, run_id=_RUN_ID)
    assert "arn:aws:s3:::alpha" in out
