"""Tests — ``compliance.summarizer`` (Task 10).

Validates the deterministic markdown renderer's layout, severity
ordering, per-section composition, and -- per Q6 of the D.9 plan --
the CIS Benchmarks® attribution footer is always emitted (including
on empty reports).
"""

from __future__ import annotations

from datetime import UTC, datetime

from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    FindingsReport,
    Severity,
    build_finding,
)
from compliance.summarizer import render_summary
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d6d6",
        tenant_id="acme",
        agent_id="compliance",
        nlah_version="d6-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _affected() -> list[AffectedResource]:
    return [
        AffectedResource(
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_iam_user",
            resource_id="alice",
            arn="arn:aws:iam::123456789012:user/alice",
        )
    ]


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="compliance",
        agent_version="0.1.0",
        customer_id="acme",
        run_id="run_d6",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, tzinfo=UTC),
        findings=[],
    )


def _aggregated_finding(
    *,
    control_id: str = "1.10",
    severity: Severity = Severity.HIGH,
    level: str = "level_1",
    required: bool = True,
    contributor_count: int = 2,
) -> ComplianceFinding:
    control_token = control_id.replace(".", "_")
    return build_finding(
        finding_id=f"COMPLIANCE-CIS_AWS_V3-{control_token}-001-aggregated",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id=control_id,
        severity=severity,
        title=f"CIS {control_id} test summary",
        description=f"Aggregated emit for {control_id}.",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "aggregated_status": "FAIL",
            "contributor_count": contributor_count,
            "contributing_finding_ids": [
                f"COMPLIANCE-CIS_AWS_V3-{control_token}-001-f3_xxx",
            ],
            "contributing_source_findings": [
                {
                    "agent": "cloud_posture",
                    "finding_id": "CSPM-AWS-IAM-001-alice",
                    "rule_id": "CSPM-AWS-IAM-001",
                }
            ],
            "control": {
                "framework": "cis_aws_v3",
                "control_id": control_id,
                "level": level,
                "required": required,
            },
        },
    )


def _report(findings: list[ComplianceFinding]) -> FindingsReport:
    report = _empty_report()
    for f in findings:
        report.add_finding(f)
    return report


# ---------------------------------------------------------------------------
# Empty / metadata
# ---------------------------------------------------------------------------


def test_empty_report_says_no_failures() -> None:
    md = render_summary(_empty_report())
    assert "# Compliance Posture — CIS AWS Foundations Benchmark v3.0" in md
    assert "Failing controls: **0**" in md
    assert "No CIS controls failed" in md


def test_empty_report_still_emits_attribution_footer() -> None:
    """Q6 license: attribution must appear even on empty reports."""
    md = render_summary(_empty_report())
    assert "CIS Benchmarks®" in md
    assert "Center for Internet Security" in md
    assert "cisecurity.org/cis-benchmarks/" in md


def test_header_metadata_includes_run_id_and_customer() -> None:
    md = render_summary(_report([_aggregated_finding()]))
    assert "Customer: `acme`" in md
    assert "Run ID: `run_d6`" in md
    assert "Failing controls: **1**" in md


# ---------------------------------------------------------------------------
# Attribution footer (always present)
# ---------------------------------------------------------------------------


def test_attribution_footer_present_with_findings() -> None:
    md = render_summary(_report([_aggregated_finding()]))
    assert "## Attribution" in md
    assert "CIS Benchmarks®" in md
    assert "paraphrased" in md
    assert "https://www.cisecurity.org/cis-benchmarks/" in md


def test_attribution_footer_is_last_section() -> None:
    md = render_summary(_report([_aggregated_finding()]))
    last_h2 = [line for line in md.splitlines() if line.startswith("## ")][-1]
    assert last_h2 == "## Attribution"


def test_attribution_explicitly_calls_out_no_verbatim_text() -> None:
    """WI-2: the attribution paragraph must mention the paraphrase posture
    so operators (and future maintainers) understand why descriptions are
    in-house rather than lifted from CIS materials."""
    md = render_summary(_report([_aggregated_finding()]))
    assert "No verbatim CIS Securesuite text is reproduced" in md


# ---------------------------------------------------------------------------
# Posture summary
# ---------------------------------------------------------------------------


def test_posture_summary_table_lists_level_1_and_level_2() -> None:
    md = render_summary(
        _report(
            [
                _aggregated_finding(control_id="1.10", level="level_1"),
                _aggregated_finding(control_id="2.4.1", level="level_2"),
            ]
        )
    )
    assert "## Posture summary" in md
    assert "CIS Level 1 (minimum-required)" in md
    assert "CIS Level 2 (defense-in-depth)" in md
    assert "| **Total** | **2** |" in md


def test_severity_breakdown_lists_all_buckets_in_order() -> None:
    md = render_summary(_report([_aggregated_finding()]))
    assert "## Severity breakdown" in md
    idx_critical = md.index("**Critical**")
    idx_high = md.index("**High**")
    idx_medium = md.index("**Medium**")
    idx_low = md.index("**Low**")
    idx_info = md.index("**Info**")
    assert idx_critical < idx_high < idx_medium < idx_low < idx_info


def test_failing_controls_breakdown_sorted_lexicographically() -> None:
    md = render_summary(
        _report(
            [
                _aggregated_finding(control_id="5.2"),
                _aggregated_finding(control_id="1.10"),
                _aggregated_finding(control_id="2.1.4"),
            ]
        )
    )
    idx_1_10 = md.index("**1.10**")
    idx_2_1_4 = md.index("**2.1.4**")
    idx_5_2 = md.index("**5.2**")
    assert idx_1_10 < idx_2_1_4 < idx_5_2


# ---------------------------------------------------------------------------
# Pinned Level-1 section
# ---------------------------------------------------------------------------


def test_level_1_section_pinned_above_findings() -> None:
    md = render_summary(
        _report(
            [
                _aggregated_finding(control_id="1.10", level="level_1"),
                _aggregated_finding(control_id="2.4.1", level="level_2"),
            ]
        )
    )
    pinned_idx = md.index("## CIS Level 1 failures")
    findings_idx = md.index("## Findings")
    assert pinned_idx < findings_idx


def test_level_1_section_includes_contributor_count() -> None:
    md = render_summary(
        _report([_aggregated_finding(control_id="1.10", level="level_1", contributor_count=3)])
    )
    assert "3 contributing source-finding(s)" in md


def test_no_level_1_section_when_only_level_2_failures() -> None:
    md = render_summary(_report([_aggregated_finding(control_id="2.4.1", level="level_2")]))
    assert "## CIS Level 1 failures" not in md


# ---------------------------------------------------------------------------
# Per-severity sections
# ---------------------------------------------------------------------------


def test_per_severity_sections_only_emitted_when_non_empty() -> None:
    md = render_summary(_report([_aggregated_finding(severity=Severity.HIGH)]))
    assert "### High (1)" in md
    assert "### Critical" not in md
    assert "### Medium" not in md
    assert "### Low" not in md


def test_per_severity_sections_in_descending_order() -> None:
    md = render_summary(
        _report(
            [
                _aggregated_finding(
                    control_id="1.10",
                    severity=Severity.HIGH,
                    level="level_1",
                ),
                _aggregated_finding(
                    control_id="2.4.1",
                    severity=Severity.CRITICAL,
                    level="level_1",
                ),
            ]
        )
    )
    idx_crit = md.index("### Critical")
    idx_high = md.index("### High")
    assert idx_crit < idx_high


def test_findings_section_carries_id_and_control_id_and_title() -> None:
    md = render_summary(_report([_aggregated_finding(control_id="1.10")]))
    assert "COMPLIANCE-CIS_AWS_V3-1_10-001-aggregated" in md
    assert "CIS 1.10" in md
    assert "test summary" in md


def test_combined_layout_renders_all_sections() -> None:
    md = render_summary(
        _report(
            [
                _aggregated_finding(
                    control_id="1.10",
                    severity=Severity.HIGH,
                    level="level_1",
                ),
                _aggregated_finding(
                    control_id="2.1.4",
                    severity=Severity.HIGH,
                    level="level_1",
                ),
                _aggregated_finding(
                    control_id="2.4.1",
                    severity=Severity.MEDIUM,
                    level="level_2",
                ),
            ]
        )
    )
    assert "## Posture summary" in md
    assert "## Severity breakdown" in md
    assert "## Failing controls" in md
    assert "## CIS Level 1 failures (2)" in md
    assert "## Findings" in md
    assert "## Attribution" in md
