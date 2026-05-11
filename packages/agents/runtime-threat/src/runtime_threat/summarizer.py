"""Render a Runtime Threat `FindingsReport` as auditor-readable markdown.

Mirrors D.2's
[`summarizer.py`](../../../packages/agents/identity/src/identity/summarizer.py)
with one structural delta: a **"Critical runtime alerts"** section is
pinned ABOVE the per-severity sections, listing every finding whose
severity is `CRITICAL` regardless of finding type. This mirrors D.1's
KEV-section pattern (CISA Known Exploited) — critical runtime alerts
are the "drop everything" signal an SRE needs in the first 30 seconds.

Layout:

1. Header + metadata
2. Severity breakdown (counts across CRITICAL → INFO)
3. Finding-type breakdown (counts across the 5 families)
4. **Critical runtime alerts** (pinned, when any exist)
5. Per-severity sections (Critical → Info), each listing the findings
"""

from __future__ import annotations

from runtime_threat.schemas import (
    FindingsReport,
    FindingType,
    RuntimeFinding,
    Severity,
)

_HEADER = "# Runtime Threat Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_FINDING_TYPE_ORDER: tuple[FindingType, ...] = (
    FindingType.PROCESS,
    FindingType.FILE,
    FindingType.NETWORK,
    FindingType.SYSCALL,
    FindingType.OSQUERY,
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
            "No runtime threats detected in this scan window.",
        ]
        return "\n".join(lines)

    findings = [RuntimeFinding(raw) for raw in report.findings]

    # Severity breakdown.
    sev_counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {sev_counts.get(sev.value, 0)}")
    lines.append("")

    # Finding-type breakdown.
    type_counts = report.count_by_finding_type()
    lines += ["## Finding-type breakdown", ""]
    for ft in _FINDING_TYPE_ORDER:
        lines.append(f"- **{ft.value}**: {type_counts.get(ft.value, 0)}")
    lines.append("")

    # Critical runtime alerts (pinned).
    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    if critical:
        lines += [
            f"## Critical runtime alerts ({len(critical)})",
            "",
            "Drop-everything alerts — investigate before any other finding family.",
            "",
        ]
        for f in critical:
            host_summary = ", ".join(f.host_ids) or "(no host)"
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Type: {f.finding_type.value}; Hosts: {host_summary}"
            )
        lines.append("")

    # Per-severity sections.
    lines += ["## Findings", ""]
    by_sev: dict[Severity, list[RuntimeFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            host_summary = ", ".join(f.host_ids) or "(no host)"
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Type: {f.finding_type.value}; Hosts: {host_summary}"
            )
        lines.append("")

    return "\n".join(lines)


__all__ = ["render_summary"]
