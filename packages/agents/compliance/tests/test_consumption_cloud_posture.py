"""compliance v0.2 Task 9 — F.3 (cloud_posture) OCSF 2003 consumption tests (WI-C2)."""

from __future__ import annotations

import asyncio

from compliance.consumption import (
    agent_ran,
    extract_failing_rule_ids,
    mapped_rules_for_agent,
    source_evaluation,
)
from compliance.tools.cis_aws_benchmark import read_cis_aws_benchmark


def _f3_report(*rule_ids: str) -> dict:
    return {
        "agent": "cloud_posture",
        "findings": [
            {"class_uid": 2003, "compliance": {"control": rid, "status": "Failed"}}
            for rid in rule_ids
        ],
    }


def test_extract_failing_rule_ids() -> None:
    report = _f3_report("CSPM-AWS-EC2-001", "CSPM-AWS-S3-001")
    assert extract_failing_rule_ids(report) == {"CSPM-AWS-EC2-001", "CSPM-AWS-S3-001"}


def test_extract_ignores_non_2003() -> None:
    report = {"findings": [{"class_uid": 2004, "compliance": {"control": "X"}}]}
    assert extract_failing_rule_ids(report) == set()


def test_mapped_rules_for_cloud_posture() -> None:
    controls = asyncio.run(read_cis_aws_benchmark())
    mapped = mapped_rules_for_agent(controls, source_agent="cloud_posture")
    # The 7 real F.3 AWS rules the library wires to.
    assert "CSPM-AWS-EC2-001" in mapped and "CSPM-AWS-IAM-002" in mapped
    assert all(r.startswith("CSPM-AWS-") for r in mapped)


def test_agent_ran() -> None:
    assert agent_ran(_f3_report()) is True  # empty findings list still = ran
    assert agent_ran({}) is False


def test_source_evaluation_agent_ran() -> None:
    controls = asyncio.run(read_cis_aws_benchmark())
    evaluated, failing = source_evaluation(
        _f3_report("CSPM-AWS-EC2-001"), controls, source_agent="cloud_posture"
    )
    assert "CSPM-AWS-EC2-001" in failing
    assert evaluated == mapped_rules_for_agent(controls, source_agent="cloud_posture")
    # EC2-001 failed; the other mapped rules (evaluated, not failing) are PASS candidates.
    assert "CSPM-AWS-S3-001" in (evaluated - failing)


def test_source_evaluation_agent_absent() -> None:
    controls = asyncio.run(read_cis_aws_benchmark())
    evaluated, failing = source_evaluation({}, controls, source_agent="cloud_posture")
    assert evaluated == set() and failing == set()  # no report -> nothing evaluated


def test_failing_intersected_with_mapped_universe() -> None:
    controls = asyncio.run(read_cis_aws_benchmark())
    # A rule F.3 emits that compliance does NOT map is ignored.
    _, failing = source_evaluation(
        _f3_report("CSPM-AWS-UNMAPPED-999"), controls, source_agent="cloud_posture"
    )
    assert failing == set()
