"""compliance v0.2 Task 10 — D.5 (multi_cloud_posture) OCSF 2003 consumption (Azure + GCP)."""

from __future__ import annotations

import asyncio

from compliance.consumption import evaluate_framework, source_evaluation
from compliance.tools.cis_azure_benchmark import read_cis_azure_benchmark
from compliance.tools.cis_gcp_benchmark import read_cis_gcp_benchmark

_AGENT = "multi_cloud_posture"


def _d5_report(*rule_ids: str) -> dict:
    # D.5 reuses F.3's build_finding, so compliance.control holds the MCSPM-* rule id.
    return {
        "agent": "multi_cloud_posture",
        "findings": [
            {"class_uid": 2003, "compliance": {"control": rid, "status": "Failed"}}
            for rid in rule_ids
        ],
    }


def test_azure_consumption_failing_and_pass() -> None:
    controls = asyncio.run(read_cis_azure_benchmark())
    evaluated, failing = source_evaluation(
        _d5_report("MCSPM-AZURE-NSG-001"), controls, source_agent=_AGENT
    )
    assert "MCSPM-AZURE-NSG-001" in failing
    assert "MCSPM-AZURE-STORAGE-002" in (evaluated - failing)  # evaluated, not failing -> PASS


def test_gcp_consumption_failing_and_pass() -> None:
    controls = asyncio.run(read_cis_gcp_benchmark())
    evaluated, failing = source_evaluation(
        _d5_report("MCSPM-GCP-FIREWALL-001"), controls, source_agent=_AGENT
    )
    assert "MCSPM-GCP-FIREWALL-001" in failing
    assert "MCSPM-GCP-BIGQUERY-001" in (evaluated - failing)


def test_azure_framework_rollup() -> None:
    controls = asyncio.run(read_cis_azure_benchmark())
    rollup = evaluate_framework(
        "cis_azure_v2", _d5_report("MCSPM-AZURE-SQL-001"), controls, source_agent=_AGENT
    )
    assert rollup.fail_count == 1  # SQL-001
    assert rollup.pass_count == 7  # the other 7 wired controls evaluated + passing
    assert rollup.not_evaluated_count == 6  # the unwired controls


def test_gcp_framework_rollup_all_pass_when_no_findings() -> None:
    controls = asyncio.run(read_cis_gcp_benchmark())
    rollup = evaluate_framework("cis_gcp_v2", _d5_report(), controls, source_agent=_AGENT)
    assert rollup.fail_count == 0 and rollup.pass_count == 10  # all 10 wired -> PASS
    assert rollup.coverage_pct > 0


def test_no_report_zero_coverage() -> None:
    controls = asyncio.run(read_cis_azure_benchmark())
    rollup = evaluate_framework("cis_azure_v2", {}, controls, source_agent=_AGENT)
    assert rollup.pass_count == 0 and rollup.fail_count == 0  # agent didn't run
