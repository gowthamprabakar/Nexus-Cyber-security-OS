"""Tests for EvalCase typed model + YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from eval_framework.cases import EvalCase, load_case_file, load_cases
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


# ---------------------------- load_case_file -------------------------------


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_load_case_file_parses_minimal_yaml(tmp_path: Path) -> None:
    p = tmp_path / "001_x.yaml"
    _write(
        p,
        """
case_id: 001_x
description: smoke
fixture:
  prowler_findings: []
expected:
  finding_count: 0
""",
    )
    case = load_case_file(p)
    assert case.case_id == "001_x"
    assert case.description == "smoke"
    assert case.expected["finding_count"] == 0


def test_load_case_file_rejects_malformed_yaml(tmp_path: Path) -> None:
    p = tmp_path / "001_bad.yaml"
    # Unclosed flow-style list — YAMLError, not just bad indent (which the
    # parser would forgive as a scalar continuation).
    _write(p, "case_id: [001, missing-close")
    with pytest.raises(ValueError, match="parse"):
        load_case_file(p)


def test_load_case_file_rejects_missing_required_fields(tmp_path: Path) -> None:
    p = tmp_path / "001_x.yaml"
    _write(p, "description: missing case_id\n")
    with pytest.raises(ValidationError):
        load_case_file(p)


def test_load_case_file_rejects_empty_yaml(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    _write(p, "")
    with pytest.raises(ValueError, match=r"empty|case"):
        load_case_file(p)


def test_load_case_file_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_case_file(tmp_path / "does-not-exist.yaml")


# ---------------------------- load_cases (directory) -----------------------


def test_load_cases_lex_sorted(tmp_path: Path) -> None:
    """Filesystem ordering may not be deterministic; the loader must sort."""
    for name in ("003_c.yaml", "001_a.yaml", "002_b.yaml"):
        _write(
            tmp_path / name,
            f"""
case_id: {name.removesuffix(".yaml")}
description: x
fixture: {{}}
expected: {{finding_count: 0}}
""",
        )
    cases = load_cases(tmp_path)
    assert [c.case_id for c in cases] == ["001_a", "002_b", "003_c"]


def test_load_cases_ignores_non_yaml_files(tmp_path: Path) -> None:
    _write(
        tmp_path / "001_x.yaml",
        "case_id: 001_x\ndescription: x\nfixture: {}\nexpected: {}\n",
    )
    _write(tmp_path / "README.md", "not a case")
    _write(tmp_path / "notes.txt", "also not a case")
    cases = load_cases(tmp_path)
    assert len(cases) == 1
    assert cases[0].case_id == "001_x"


def test_load_cases_rejects_duplicate_case_ids(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.yaml",
        "case_id: dup\ndescription: a\nfixture: {}\nexpected: {}\n",
    )
    _write(
        tmp_path / "b.yaml",
        "case_id: dup\ndescription: b\nfixture: {}\nexpected: {}\n",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_cases(tmp_path)


def test_load_cases_empty_directory_returns_empty_list(tmp_path: Path) -> None:
    assert load_cases(tmp_path) == []


def test_load_cases_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_cases(tmp_path / "does-not-exist")


def test_load_cases_loads_cloud_posture_suite_unchanged() -> None:
    """The 10 cloud-posture cases must load through the new framework
    without modification — proves the schema fits real-world fixtures."""
    # parents[0]=tests, [1]=eval-framework, [2]=packages
    cloud_posture_cases = (
        Path(__file__).resolve().parents[2] / "agents" / "cloud-posture" / "eval" / "cases"
    )
    if not cloud_posture_cases.is_dir():
        pytest.skip(f"shipped cases not found at {cloud_posture_cases}")

    cases = load_cases(cloud_posture_cases)
    assert len(cases) == 10
    case_ids = [c.case_id for c in cases]
    assert "001_public_s3_bucket" in case_ids
    assert "010_unencrypted_ebs_volume" in case_ids
    # Lex-sorted by load_cases
    assert case_ids == sorted(case_ids)
