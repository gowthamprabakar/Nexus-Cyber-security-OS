"""Tests for EvalCase typed model (full loader lands in Task 3)."""

from __future__ import annotations

import pytest
from eval_framework.cases import EvalCase
from pydantic import ValidationError


def test_eval_case_round_trip() -> None:
    case = EvalCase(
        case_id="001_public_s3_bucket",
        description="Public S3 bucket should produce one high-severity finding",
        fixture={"prowler_findings": [], "iam_users_without_mfa": []},
        expected={"finding_count": 1, "has_severity": {"high": 1}},
        tags=["cspm", "s3"],
        timeout_sec=60.0,
    )
    rebuilt = EvalCase.model_validate_json(case.model_dump_json())
    assert rebuilt == case


def test_eval_case_defaults() -> None:
    case = EvalCase(case_id="001_x", description="d", fixture={}, expected={})
    assert case.tags == []
    assert case.timeout_sec == 60.0


def test_eval_case_is_frozen() -> None:
    case = EvalCase(case_id="001_x", description="d", fixture={}, expected={})
    with pytest.raises(ValidationError):
        case.case_id = "002_y"  # type: ignore[misc]


def test_eval_case_rejects_empty_case_id() -> None:
    with pytest.raises(ValidationError):
        EvalCase(case_id="", description="d", fixture={}, expected={})


def test_eval_case_rejects_negative_timeout() -> None:
    with pytest.raises(ValidationError):
        EvalCase(
            case_id="001",
            description="d",
            fixture={},
            expected={},
            timeout_sec=-1.0,
        )
