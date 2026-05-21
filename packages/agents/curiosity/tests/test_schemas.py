"""Tests — `curiosity.schemas` (Task 2).

20 tests covering:

1-3. CoverageGap field validation (region non-empty, asset_count
     non-negative, days_since_last_finding non-negative).
4. CoverageGap is frozen.
5-7. ProbeDirective exactly-one-of constraint (XOR over
     target_resource_arn / target_finding_id; both raises, neither
     raises, one each accepted).
8. ProbeDirective.action must be a ProbeAction enum.
9. ProbeDirective.target_agent must be a TargetAgent enum.
10. Hypothesis statement/rationale length caps enforced.
11-13. CuriosityClaim ULID validation (good ULID, malformed, wrong
     length).
14. CuriosityClaim.agent_id literal pinned to "curiosity".
15. CuriosityDraft hypothesis-count cap (≤5).
16. CuriosityDraft default-empty construction.
17. CuriosityReport.total_claims property.
18. CuriosityReport.total_gaps_addressed dedup.
19. CuriosityReport.review_retries non-negative.
20. JSON round-trip (CuriosityClaim model_dump_json -> model_validate_json).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from curiosity.schemas import (
    CoverageGap,
    CuriosityClaim,
    CuriosityDraft,
    CuriosityReport,
    Hypothesis,
    ProbeAction,
    ProbeDirective,
    TargetAgent,
)
from pydantic import ValidationError

_VALID_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


def _gap(**overrides: Any) -> CoverageGap:
    defaults: dict[str, Any] = {
        "region": "us-east-1",
        "asset_count": 42,
        "days_since_last_finding": 35,
        "severity_hint": "medium",
    }
    defaults.update(overrides)
    return CoverageGap(**defaults)


def _directive(**overrides: Any) -> ProbeDirective:
    defaults: dict[str, Any] = {
        "target_agent": TargetAgent.DATA_SECURITY,
        "target_resource_arn": "arn:aws:s3:::eu-west-3-bucket",
        "action": ProbeAction.SCAN,
        "rationale_ref": _VALID_ULID,
    }
    defaults.update(overrides)
    return ProbeDirective(**defaults)


def _hypothesis(**overrides: Any) -> Hypothesis:
    defaults: dict[str, Any] = {
        "statement": "The eu-west-3 region has 42 assets but no scans in 35 days.",
        "rationale": (
            "F.3 Cloud Posture and D.5 Data Security have not surfaced any findings "
            "for assets in eu-west-3 within the last 30 days, despite an inventory of "
            "42 entities. This is consistent with a coverage gap rather than a clean "
            "posture. Recommend running D.5 across the region's S3 buckets to "
            "establish a baseline."
        ),
        "probe_directive": _directive(),
        "cited_gap": _gap(),
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)


def _claim(**overrides: Any) -> CuriosityClaim:
    defaults: dict[str, Any] = {
        "claim_id": _VALID_ULID,
        "customer_id": "acme",
        "hypothesis": _hypothesis(),
        "emitted_at": datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return CuriosityClaim(**defaults)


# ---------------------------------------------------------------------------
# CoverageGap
# ---------------------------------------------------------------------------


def test_coverage_gap_rejects_empty_region() -> None:
    with pytest.raises(ValidationError, match="region"):
        _gap(region="")


def test_coverage_gap_rejects_negative_asset_count() -> None:
    with pytest.raises(ValidationError):
        _gap(asset_count=-1)


def test_coverage_gap_rejects_negative_days() -> None:
    with pytest.raises(ValidationError):
        _gap(days_since_last_finding=-1)


def test_coverage_gap_is_frozen() -> None:
    gap = _gap()
    with pytest.raises((TypeError, ValidationError)):
        gap.region = "elsewhere"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ProbeDirective — exactly-one-of constraint
# ---------------------------------------------------------------------------


def test_probe_directive_rejects_both_targets() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        _directive(target_resource_arn="arn:x", target_finding_id="F-1")


def test_probe_directive_rejects_neither_target() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        _directive(target_resource_arn=None, target_finding_id=None)


def test_probe_directive_accepts_finding_id_only() -> None:
    d = _directive(target_resource_arn=None, target_finding_id="CSPM-AWS-IAM-001-alice")
    assert d.target_finding_id == "CSPM-AWS-IAM-001-alice"
    assert d.target_resource_arn is None


def test_probe_directive_action_must_be_enum() -> None:
    with pytest.raises(ValidationError):
        _directive(action="run-the-scan")  # type: ignore[arg-type]


def test_probe_directive_target_agent_must_be_enum() -> None:
    with pytest.raises(ValidationError):
        _directive(target_agent="compliance")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------


def test_hypothesis_statement_max_length_enforced() -> None:
    with pytest.raises(ValidationError):
        _hypothesis(statement="x" * 401)


def test_hypothesis_rationale_max_length_enforced() -> None:
    with pytest.raises(ValidationError):
        _hypothesis(rationale="x" * 1501)


# ---------------------------------------------------------------------------
# CuriosityClaim — ULID validation + agent_id literal
# ---------------------------------------------------------------------------


def test_claim_accepts_valid_ulid() -> None:
    c = _claim()
    assert c.claim_id == _VALID_ULID


def test_claim_rejects_malformed_ulid() -> None:
    """26-char string that isn't valid Crockford base32 (O is forbidden)."""
    with pytest.raises(ValidationError, match="ULID"):
        _claim(claim_id="OOOOOOOOOOOOOOOOOOOOOOOOOO")


def test_claim_rejects_wrong_length_string() -> None:
    """ULIDs are exactly 26 chars; field's min/max enforce shape."""
    with pytest.raises(ValidationError):
        _claim(claim_id="01J7M3X9Z1")  # too short


def test_claim_agent_id_pinned_to_curiosity() -> None:
    """The Literal["curiosity"] constraint rejects other agent_ids."""
    with pytest.raises(ValidationError):
        _claim(agent_id="meta_harness")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CuriosityDraft
# ---------------------------------------------------------------------------


def test_draft_caps_hypothesis_count_at_five() -> None:
    """Plan §"Per-run caps": max 5 hypotheses per run."""
    h = _hypothesis()
    with pytest.raises(ValidationError):
        CuriosityDraft(hypotheses=(h, h, h, h, h, h))  # 6 — over the cap


def test_draft_default_construction_is_empty() -> None:
    d = CuriosityDraft()
    assert d.hypotheses == ()
    assert d.llm_call_count == 0
    assert d.total_tokens_used == 0


# ---------------------------------------------------------------------------
# CuriosityReport — property accessors + validation
# ---------------------------------------------------------------------------


def test_report_total_claims_property() -> None:
    r = CuriosityReport(
        customer_id="acme",
        run_id="run-1",
        scan_started_at=datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 12, 5, tzinfo=UTC),
        claims=[_claim(), _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG0")],
    )
    assert r.total_claims == 2


def test_report_total_gaps_addressed_dedupes_by_region() -> None:
    """Multiple hypotheses against the same region count as ONE gap addressed."""
    gap_a = _gap(region="eu-west-3")
    gap_b = _gap(region="ap-south-1")
    h_a1 = _hypothesis(cited_gap=gap_a)
    h_a2 = _hypothesis(cited_gap=gap_a)  # same region
    h_b = _hypothesis(cited_gap=gap_b)
    r = CuriosityReport(
        customer_id="acme",
        run_id="run-1",
        scan_started_at=datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 12, 5, tzinfo=UTC),
        claims=[
            _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ", hypothesis=h_a1),
            _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG0", hypothesis=h_a2),
            _claim(claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG1", hypothesis=h_b),
        ],
    )
    assert r.total_claims == 3
    assert r.total_gaps_addressed == 2


def test_report_review_retries_non_negative() -> None:
    with pytest.raises(ValidationError):
        CuriosityReport(
            customer_id="acme",
            run_id="run-1",
            scan_started_at=datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
            scan_completed_at=datetime(2026, 5, 21, 12, 5, tzinfo=UTC),
            review_retries=-1,
        )


# ---------------------------------------------------------------------------
# JSON round-trip — the on-the-wire shape
# ---------------------------------------------------------------------------


def test_claim_json_round_trip() -> None:
    """CuriosityClaim must serialise + deserialise byte-for-byte. This
    is the on-the-wire shape that lands on claims.> in Task 9."""
    original = _claim()
    raw = original.model_dump_json()
    restored = CuriosityClaim.model_validate_json(raw)
    assert restored == original
