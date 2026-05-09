"""Render a FindingsReport as auditor-readable markdown.

Consumes the OCSF v1.3 wire format that lives in `FindingsReport.findings`
(per ADR-004 / Task 6.5). Each raw dict is wrapped in a `CloudPostureFinding`
for typed access; the resources list is read from the OCSF `resources` array
(`{"type", "uid", "cloud_partition", "region", "owner": {"account_uid"}}`).
"""

from __future__ import annotations

from cloud_posture.schemas import (
    CloudPostureFinding,
    FindingsReport,
    Severity,
)

_HEADER = "# Cloud Posture Scan"

# High → Low ordering for both the breakdown counts and the per-severity sections.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def render_summary(report: FindingsReport) -> str:
    lines: list[str] = [
        _HEADER,
        "",
        f"- Customer: `{report.customer_id}`",
        f"- Run ID: `{report.run_id}`",
        (
            f"- Scan window: {report.scan_started_at.isoformat()} → "
            f"{report.scan_completed_at.isoformat()}"
        ),
        f"- Total findings: **{report.total}**",
        "",
    ]

    if report.total == 0:
        lines += [
            "## Summary",
            "",
            "No findings detected in this scan window.",
        ]
        return "\n".join(lines)

    counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {counts.get(sev.value, 0)}")
    lines += ["", "## Findings", ""]

    findings = [CloudPostureFinding(raw) for raw in report.findings]
    by_sev: dict[Severity, list[CloudPostureFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            arns = ", ".join(_arn_of(r) for r in f.resources)
            lines.append(f"- `{f.finding_id}` — {f.title}  \n  Affected: {arns}")
        lines.append("")

    return "\n".join(lines)


def _arn_of(ocsf_resource: dict[str, object]) -> str:
    """Extract the ARN from an OCSF ResourceDetails row.

    AffectedResource.to_ocsf maps `arn` → `uid`; we read it back here so the
    summary stays human-readable regardless of cloud partition.
    """
    uid = ocsf_resource.get("uid")
    return str(uid) if uid is not None else "<unknown>"
