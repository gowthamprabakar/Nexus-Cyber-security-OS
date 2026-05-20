"""Tests — ``data_security.correlate``.

Task 9. F.3 cross-correlation:

- Reader handles missing workspace file → empty tuple.
- Reader handles malformed JSON → empty tuple (forgiving).
- Reader extracts findings from canonical FindingsReport shape.
- Reader extracts findings from bare-list shape.
- ``correlate_with_f3`` matches by bucket ARN.
- D.5 finding with no F.3 match → not in result map.
- D.5 finding with multiple F.3 matches → all listed.
- Multiple D.5 findings on same bucket → all matched.
- ARN index handles duplicate ARNs in F.3 (one finding per ARN counted).
- Empty inputs → empty result.
- ``matches_for`` / ``matched_d5_finding_count`` API.
- Pure function (no module state).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from data_security.correlate import (
    CorrelationResult,
    correlate_with_f3,
    read_f3_findings,
)
from data_security.detectors.public_bucket import detect_public_bucket
from data_security.schemas import ClassifierLabel
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


def _make_public_bucket(name: str = "corp-data-lake") -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(grants_all_users=["READ"]),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="AES256"),
    )


def _make_f3_finding(*, finding_id: str, bucket_arn: str) -> dict:
    """Minimal F.3-shaped finding payload sufficient for ARN matching."""
    return {
        "class_uid": 2003,
        "finding_info": {"uid": finding_id, "title": "f.3 finding"},
        "resources": [{"uid": bucket_arn, "type": "s3-bucket"}],
    }


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# read_f3_findings — reader behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_f3_findings_missing_file_returns_empty(tmp_path: Path) -> None:
    """No findings.json under workspace → empty tuple, no error."""
    result = await read_f3_findings(tmp_path)
    assert result == ()


@pytest.mark.asyncio
async def test_read_f3_findings_canonical_shape(tmp_path: Path) -> None:
    """FindingsReport canonical shape: ``{"findings": [...]}``."""
    findings = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-001-bucket-a", bucket_arn="arn:aws:s3:::a"),
        _make_f3_finding(finding_id="CSPM-AWS-PROW-002-bucket-b", bucket_arn="arn:aws:s3:::b"),
    ]
    report = {
        "agent": "cloud-posture",
        "agent_version": "0.1.0",
        "findings": findings,
    }
    (tmp_path / "findings.json").write_text(json.dumps(report), encoding="utf-8")
    result = await read_f3_findings(tmp_path)
    assert len(result) == 2
    assert result[0]["finding_info"]["uid"] == "CSPM-AWS-PROW-001-bucket-a"


@pytest.mark.asyncio
async def test_read_f3_findings_bare_list_shape(tmp_path: Path) -> None:
    """Bare top-level list also accepted."""
    findings = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-001-bucket-a", bucket_arn="arn:aws:s3:::a")
    ]
    (tmp_path / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    result = await read_f3_findings(tmp_path)
    assert len(result) == 1


@pytest.mark.asyncio
async def test_read_f3_findings_malformed_json_returns_empty(tmp_path: Path) -> None:
    """Malformed JSON does NOT raise — empty tuple instead."""
    (tmp_path / "findings.json").write_text("{not valid", encoding="utf-8")
    result = await read_f3_findings(tmp_path)
    assert result == ()


@pytest.mark.asyncio
async def test_read_f3_findings_unrecognised_top_level_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("42", encoding="utf-8")
    result = await read_f3_findings(tmp_path)
    assert result == ()


@pytest.mark.asyncio
async def test_read_f3_findings_non_dict_entries_skipped(tmp_path: Path) -> None:
    """Non-dict entries in the findings list are filtered out."""
    report = {
        "findings": [
            "not-a-dict",
            42,
            None,
            _make_f3_finding(finding_id="CSPM-AWS-PROW-001-bucket-a", bucket_arn="arn:aws:s3:::a"),
        ]
    }
    (tmp_path / "findings.json").write_text(json.dumps(report), encoding="utf-8")
    result = await read_f3_findings(tmp_path)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# correlate_with_f3 — matching logic
# ---------------------------------------------------------------------------


def test_correlate_matches_by_bucket_arn() -> None:
    """D.5 finding on bucket X matches F.3 finding on bucket X."""
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(d5) == 1

    f3 = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-005-alpha", bucket_arn="arn:aws:s3:::alpha"),
    ]
    result = correlate_with_f3(d5, f3)
    assert result.matches_for(d5[0].finding_id) == ["CSPM-AWS-PROW-005-alpha"]


def test_correlate_no_match_d5_finding_absent_from_map() -> None:
    """D.5 finding on bucket X + F.3 finding on bucket Y → no match
    (D.5 finding-id not in result.matches at all).
    """
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    f3 = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-005-other", bucket_arn="arn:aws:s3:::other"),
    ]
    result = correlate_with_f3(d5, f3)
    assert result.matches_for(d5[0].finding_id) == []
    assert d5[0].finding_id not in result.matches


def test_correlate_multiple_f3_findings_per_bucket() -> None:
    """Multiple F.3 findings on the same bucket all surface in the match list."""
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    f3 = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-001-alpha", bucket_arn="arn:aws:s3:::alpha"),
        _make_f3_finding(finding_id="CSPM-AWS-PROW-002-alpha", bucket_arn="arn:aws:s3:::alpha"),
        _make_f3_finding(finding_id="CSPM-AWS-PROW-003-other", bucket_arn="arn:aws:s3:::other"),
    ]
    result = correlate_with_f3(d5, f3)
    matches = result.matches_for(d5[0].finding_id)
    assert sorted(matches) == ["CSPM-AWS-PROW-001-alpha", "CSPM-AWS-PROW-002-alpha"]


def test_correlate_multiple_d5_findings_same_bucket() -> None:
    """Two D.5 findings on the same bucket both match the same F.3 finding."""
    bucket = _make_public_bucket("alpha")
    d5_a = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=1)
    d5_b = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=2)
    all_d5 = d5_a + d5_b
    assert all_d5[0].finding_id != all_d5[1].finding_id

    f3 = [_make_f3_finding(finding_id="CSPM-AWS-PROW-001-alpha", bucket_arn="arn:aws:s3:::alpha")]
    result = correlate_with_f3(all_d5, f3)
    assert result.matches_for(all_d5[0].finding_id) == ["CSPM-AWS-PROW-001-alpha"]
    assert result.matches_for(all_d5[1].finding_id) == ["CSPM-AWS-PROW-001-alpha"]


def test_correlate_empty_inputs() -> None:
    result = correlate_with_f3([], [])
    assert result.matches == {}
    assert result.raw_f3_finding_count == 0
    assert result.matched_d5_finding_count == 0


def test_correlate_empty_f3_only() -> None:
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    result = correlate_with_f3(d5, [])
    assert result.matches == {}
    assert result.raw_f3_finding_count == 0


def test_correlate_empty_d5_only() -> None:
    f3 = [_make_f3_finding(finding_id="CSPM-AWS-PROW-001-alpha", bucket_arn="arn:aws:s3:::alpha")]
    result = correlate_with_f3([], f3)
    assert result.matches == {}
    assert result.raw_f3_finding_count == 1


def test_correlate_records_raw_f3_count() -> None:
    """``raw_f3_finding_count`` records ALL F.3 findings, including unmatched."""
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    f3 = [
        _make_f3_finding(
            finding_id=f"CSPM-AWS-PROW-00{i}-other", bucket_arn=f"arn:aws:s3:::other-{i}"
        )
        for i in range(5)
    ]
    result = correlate_with_f3(d5, f3)
    assert result.raw_f3_finding_count == 5
    # No matches.
    assert result.matched_d5_finding_count == 0


def test_correlate_handles_malformed_f3_findings() -> None:
    """F.3 finding without ``finding_info.uid`` or ``resources`` → skipped silently."""
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    f3 = [
        {"missing": "everything"},  # no finding_info, no resources
        {"finding_info": {"uid": ""}},  # empty uid
        {"finding_info": {"uid": "CSPM-AWS-PROW-001"}, "resources": "not-a-list"},
        _make_f3_finding(finding_id="CSPM-AWS-PROW-005-alpha", bucket_arn="arn:aws:s3:::alpha"),
    ]
    result = correlate_with_f3(d5, f3)
    # Only the well-formed finding matches.
    assert result.matches_for(d5[0].finding_id) == ["CSPM-AWS-PROW-005-alpha"]
    # raw_f3_finding_count counts all 4 (regardless of shape).
    assert result.raw_f3_finding_count == 4


def test_correlation_result_immutable() -> None:
    """``CorrelationResult`` is a frozen dataclass."""
    from dataclasses import FrozenInstanceError

    result = CorrelationResult(matches={"a": ["b"]}, raw_f3_finding_count=1)
    with pytest.raises(FrozenInstanceError):
        result.matches = {}  # type: ignore[misc]


def test_correlation_result_matches_for_returns_copy() -> None:
    """``matches_for`` returns a defensive copy; mutating it doesn't affect the result."""
    result = CorrelationResult(matches={"d5-1": ["f3-1"]})
    out = result.matches_for("d5-1")
    out.append("INJECTED")
    # Internal mapping is unchanged.
    assert result.matches["d5-1"] == ["f3-1"]


def test_correlation_module_no_module_state() -> None:
    from data_security import correlate as correlate_module

    snapshot_before = {
        k: id(v) for k, v in vars(correlate_module).items() if not k.startswith("__")
    }
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    f3 = [_make_f3_finding(finding_id="CSPM-AWS-PROW-001-alpha", bucket_arn="arn:aws:s3:::alpha")]
    for _ in range(10):
        correlate_with_f3(d5, f3)
    snapshot_after = {k: id(v) for k, v in vars(correlate_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after


# ---------------------------------------------------------------------------
# Integration smoke — reader + correlate composition
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_then_correlate_end_to_end(tmp_path: Path) -> None:
    """End-to-end: read F.3 workspace → correlate against D.5 findings."""
    f3_findings = [
        _make_f3_finding(finding_id="CSPM-AWS-PROW-001-alpha", bucket_arn="arn:aws:s3:::alpha"),
        _make_f3_finding(finding_id="CSPM-AWS-PROW-002-beta", bucket_arn="arn:aws:s3:::beta"),
    ]
    (tmp_path / "findings.json").write_text(json.dumps({"findings": f3_findings}), encoding="utf-8")

    bucket_alpha = _make_public_bucket("alpha")
    bucket_beta = _make_public_bucket("beta")
    bucket_gamma = _make_public_bucket("gamma")  # not in F.3
    d5 = (
        detect_public_bucket(bucket_alpha, envelope=_make_envelope(), detected_at=_TS, sequence=1)
        + detect_public_bucket(bucket_beta, envelope=_make_envelope(), detected_at=_TS, sequence=2)
        + detect_public_bucket(bucket_gamma, envelope=_make_envelope(), detected_at=_TS, sequence=3)
    )

    f3 = await read_f3_findings(tmp_path)
    result = correlate_with_f3(d5, f3)

    # alpha + beta match; gamma doesn't.
    alpha_id = next(f.finding_id for f in d5 if "alpha" in f.finding_id)
    beta_id = next(f.finding_id for f in d5 if "beta" in f.finding_id)
    gamma_id = next(f.finding_id for f in d5 if "gamma" in f.finding_id)

    assert result.matches_for(alpha_id) == ["CSPM-AWS-PROW-001-alpha"]
    assert result.matches_for(beta_id) == ["CSPM-AWS-PROW-002-beta"]
    assert result.matches_for(gamma_id) == []
    assert result.matched_d5_finding_count == 2
    assert result.raw_f3_finding_count == 2


# ---------------------------------------------------------------------------
# Q6 — no PII leak through correlation
# ---------------------------------------------------------------------------


def test_correlation_does_not_expose_classifier_payloads() -> None:
    """The correlation module operates on finding IDs and ARNs only. It must
    never read or expose classifier-content fields.
    """
    # Build a D.5 finding with classifier hits → its evidence carries label
    # strings. Correlate against an F.3 finding with malicious evidence shape.
    bucket = _make_public_bucket("alpha")
    d5 = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    f3_with_payload = {
        "class_uid": 2003,
        "finding_info": {"uid": "CSPM-AWS-PROW-001-alpha"},
        "resources": [{"uid": "arn:aws:s3:::alpha"}],
        "evidences": [{"matched_text": "MUST-NOT-LEAK-123-45-6789"}],
    }
    result = correlate_with_f3(d5, [f3_with_payload])
    # Correlation result must contain ONLY finding IDs, not payloads.
    serialized = json.dumps(result.matches)
    assert "MUST-NOT-LEAK" not in serialized
    assert "123-45-6789" not in serialized
