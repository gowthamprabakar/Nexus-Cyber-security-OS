"""compliance v0.2 Task 14 — continuous + heartbeat coexistence tests (WI-C10)."""

from __future__ import annotations

import asyncio

from compliance.continuous.mode import (
    DEFAULT_MODE,
    MonitoringMode,
    evaluate_for_mode,
    modes_coexist,
    select_mode,
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


def test_default_is_heartbeat() -> None:
    # WI-C10: heartbeat default, continuous never preempts.
    assert DEFAULT_MODE == MonitoringMode.HEARTBEAT
    assert select_mode({}) == MonitoringMode.HEARTBEAT


def test_select_continuous() -> None:
    assert select_mode({"compliance_monitoring_mode": "continuous"}) == MonitoringMode.CONTINUOUS


def test_select_case_insensitive() -> None:
    assert select_mode({"compliance_monitoring_mode": "CONTINUOUS"}) == MonitoringMode.CONTINUOUS


def test_invalid_mode_falls_back_to_default() -> None:
    assert select_mode({"compliance_monitoring_mode": "bogus"}) == DEFAULT_MODE


def test_modes_coexist() -> None:
    assert modes_coexist() is True


def test_both_modes_equivalent_results() -> None:
    # The defining coexistence property: identical inputs -> identical rollups.
    controls = asyncio.run(read_cis_aws_benchmark())
    report = _f3_report("CSPM-AWS-EC2-001")
    hb = evaluate_for_mode(
        MonitoringMode.HEARTBEAT, "cis_aws_v3", report, controls, source_agent="cloud_posture"
    )
    cont = evaluate_for_mode(
        MonitoringMode.CONTINUOUS, "cis_aws_v3", report, controls, source_agent="cloud_posture"
    )
    assert hb == cont
    assert hb.fail_count >= 1
