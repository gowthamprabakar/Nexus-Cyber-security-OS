"""Unit tests for the fleet-test L2 capability evaluator (fleet_testkit.capability).

Tests the P/R/FP math + YAML loader/validator with synthetic data — no agent dependency. The
evaluator is the shared infra all 20 L2 banks consume, so its scoring must be provably correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fleet_testkit import (
    GroundTruth,
    NonDetection,
    PassCriteria,
    evaluate,
    load_test_case,
    score,
)
from fleet_testkit.capability import detection_timer


# A finding is just a (type, resource) pair here; the per-agent match key is supplied to score().
def _match(finding: tuple[str, str], gt: GroundTruth) -> bool:
    return finding[0] == gt.type and finding[1] == gt.resource


_GT = [
    GroundTruth(id="GT-1", type="cve", resource="img:a"),
    GroundTruth(id="GT-2", type="cve", resource="img:b"),
]


# ---------------------------- scoring math -------------------------------


def test_perfect_detection() -> None:
    result = score(
        [("cve", "img:a"), ("cve", "img:b")], _GT, match=_match, label=lambda f: f"{f[0]}:{f[1]}"
    )
    assert result.true_positives == 2
    assert result.false_negatives == 0
    assert result.false_positives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_false_negative_lowers_recall() -> None:
    result = score([("cve", "img:a")], _GT, match=_match)
    assert result.true_positives == 1
    assert result.false_negatives == 1
    assert result.recall == 0.5
    assert result.precision == 1.0
    assert result.missed == ("GT-2",)


def test_false_positive_lowers_precision() -> None:
    result = score(
        [("cve", "img:a"), ("cve", "img:b"), ("cve", "img:ZZZ")],
        _GT,
        match=_match,
        label=lambda f: f"{f[0]}:{f[1]}",
    )
    assert result.true_positives == 2
    assert result.false_positives == 1
    assert result.recall == 1.0
    assert result.precision == 2 / 3
    assert result.spurious == ("cve:img:ZZZ",)


def test_fp_trap_counts_as_false_positive() -> None:
    # A finding on a non-detection resource matches no ground truth → FP.
    nds = [NonDetection(id="ND-1", resource="img:legit", reason="patched base layer")]
    result = score([("cve", "img:legit")], _GT, non_detections=nds, match=_match)
    assert result.false_positives == 1
    assert result.true_positives == 0


def test_clean_baseline_no_findings_is_perfect() -> None:
    # 0 ground truth + 0 findings → precision & recall default to 1.0 (no division by zero).
    result = score([], [], match=_match)
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.false_positives == 0


def test_clean_baseline_with_a_finding_is_a_false_positive() -> None:
    result = score([("cve", "img:a")], [], match=_match, label=lambda f: f"{f[0]}:{f[1]}")
    assert result.false_positives == 1
    assert result.precision == 0.0  # 0 TP / (0 TP + 1 FP)


def test_one_finding_matching_two_gts_counts_both() -> None:
    # A broad finding that matches multiple ground truths credits each (TP by ground truth).
    gts = [
        GroundTruth(id="GT-1", type="open", resource="r"),
        GroundTruth(id="GT-2", type="open", resource="r"),
    ]
    result = score([("open", "r")], gts, match=lambda f, g: f[0] == g.type and f[1] == g.resource)
    assert result.true_positives == 2
    assert result.false_positives == 0


# ---------------------------- evaluate gating ----------------------------


def test_evaluate_passes_when_thresholds_met() -> None:
    result = score([("cve", "img:a"), ("cve", "img:b")], _GT, match=_match)
    evaluate(result, PassCriteria(precision=0.95, recall=0.95, false_positives_max=0))


def test_evaluate_fails_on_low_recall() -> None:
    result = score([("cve", "img:a")], _GT, match=_match, test_case_id="TC-1")
    with pytest.raises(AssertionError, match=r"recall 0\.500 < 0\.95"):
        evaluate(result, PassCriteria(recall=0.95))


def test_evaluate_fails_on_low_precision() -> None:
    result = score(
        [("cve", "img:a"), ("cve", "img:b"), ("cve", "x")],
        _GT,
        match=_match,
        label=lambda f: f"{f[0]}:{f[1]}",
        test_case_id="TC-2",
    )
    with pytest.raises(AssertionError, match=r"precision 0\.667 < 0\.95"):
        evaluate(result, PassCriteria(precision=0.95))


def test_evaluate_fails_on_fp_ceiling() -> None:
    result = score([("cve", "x")], [], match=_match, test_case_id="TC-3")
    with pytest.raises(AssertionError, match=r"false_positives 1 > 0"):
        evaluate(result, PassCriteria(false_positives_max=0))


def test_evaluate_fails_on_detection_time() -> None:
    result = score([], [], match=_match, detection_time_seconds=2.0, test_case_id="TC-4")
    with pytest.raises(AssertionError, match=r"detection_time 2\.000s > 1\.0s"):
        evaluate(result, PassCriteria(detection_time_max_seconds=1.0))


def test_detection_timer_measures() -> None:
    with detection_timer() as t:
        pass
    assert t.seconds >= 0.0


# ---------------------------- YAML loader / validator --------------------

_VALID_YAML = """\
test_case_id: "TC-VULN-001"
description: "critical CVE on a deployed image"
agent: "vulnerability"
category: "standard_violations"
environment:
  fixture_path: "fixtures/one_cve.yaml"
  realism_notes: "Trivy JSON for a known CVE on python:3.11-slim"
ground_truth_violations:
  - id: "GT-001"
    type: "cve"
    resource: "img:python-3.11-slim"
    severity: "critical"
    expected_detect: true
expected_non_detections:
  - id: "ND-001"
    resource: "img:patched"
    reason: "fixed version installed"
    expected_detect: false
pass_criteria:
  precision: ">= 0.95"
  recall: ">= 0.95"
  false_positives_max: 0
  detection_time_max_seconds: 30
"""


def test_load_valid_case(tmp_path: Path) -> None:
    p = tmp_path / "tc.yaml"
    p.write_text(_VALID_YAML)
    tc = load_test_case(p)
    assert tc.test_case_id == "TC-VULN-001"
    assert tc.agent == "vulnerability"
    assert tc.category == "standard_violations"
    assert tc.fixture_path == "fixtures/one_cve.yaml"
    assert len(tc.ground_truth_violations) == 1
    assert tc.ground_truth_violations[0].resource == "img:python-3.11-slim"
    assert len(tc.expected_non_detections) == 1
    assert tc.pass_criteria.precision == 0.95  # ">= 0.95" parsed
    assert tc.pass_criteria.false_positives_max == 0
    assert tc.pass_criteria.detection_time_max_seconds == 30.0


def test_load_rejects_missing_key(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(_VALID_YAML.replace("pass_criteria:", "wrong_key:"))
    with pytest.raises(ValueError, match=r"missing required key 'pass_criteria'"):
        load_test_case(p)


def test_load_rejects_bad_category(tmp_path: Path) -> None:
    p = tmp_path / "badcat.yaml"
    p.write_text(_VALID_YAML.replace("standard_violations", "made_up_category"))
    with pytest.raises(ValueError, match=r"category 'made_up_category' not in"):
        load_test_case(p)


def test_load_rejects_nonbaseline_without_ground_truth(tmp_path: Path) -> None:
    yaml_text = _VALID_YAML.replace(
        'ground_truth_violations:\n  - id: "GT-001"\n    type: "cve"\n'
        '    resource: "img:python-3.11-slim"\n    severity: "critical"\n'
        "    expected_detect: true",
        "ground_truth_violations: []",
    )
    p = tmp_path / "empty.yaml"
    p.write_text(yaml_text)
    with pytest.raises(ValueError, match=r"non-baseline case must list >=1"):
        load_test_case(p)


def test_load_allows_clean_baseline_without_ground_truth(tmp_path: Path) -> None:
    yaml_text = _VALID_YAML.replace("standard_violations", "clean_baseline").replace(
        'ground_truth_violations:\n  - id: "GT-001"\n    type: "cve"\n'
        '    resource: "img:python-3.11-slim"\n    severity: "critical"\n'
        "    expected_detect: true",
        "ground_truth_violations: []",
    )
    p = tmp_path / "baseline.yaml"
    p.write_text(yaml_text)
    tc = load_test_case(p)
    assert tc.category == "clean_baseline"
    assert tc.ground_truth_violations == ()


def test_load_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"file not found"):
        load_test_case(tmp_path / "nope.yaml")
