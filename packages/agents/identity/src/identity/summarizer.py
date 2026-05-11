"""Render an Identity `FindingsReport` as auditor-readable markdown.

Mirrors D.1's
[`summarizer.py`](../../../packages/agents/vulnerability/src/vulnerability/summarizer.py)
with one structural delta: a **"High-risk principals"** section is
pinned ABOVE the per-severity sections, listing every principal that
appears in an OVERPRIVILEGE, EXTERNAL_ACCESS, or MFA_GAP finding.
Dormancy alone is not "high-risk" — a stale user with no admin grants
is hygiene, not danger — so dormant-only principals are not surfaced
here. (They still show up in the per-severity breakdown below.)

The markdown-summarizer pattern carries over verbatim from D.1 and F.3:
same FindingsReport input, same top-down layout, same `str` return.
"""

from __future__ import annotations

from identity.schemas import (
    FindingsReport,
    FindingType,
    IdentityFinding,
    Severity,
)

_HEADER = "# Identity Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_FINDING_TYPE_ORDER: tuple[FindingType, ...] = (
    FindingType.OVERPRIVILEGE,
    FindingType.EXTERNAL_ACCESS,
    FindingType.MFA_GAP,
    FindingType.ADMIN_PATH,
    FindingType.DORMANT,
)

_HIGH_RISK_TYPES: frozenset[FindingType] = frozenset(
    {FindingType.OVERPRIVILEGE, FindingType.EXTERNAL_ACCESS, FindingType.MFA_GAP}
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
            "No identity risk detected in this scan window.",
        ]
        return "\n".join(lines)

    findings = [IdentityFinding(raw) for raw in report.findings]

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

    # High-risk principals (pinned).
    high_risk_arns = _high_risk_principal_arns(findings)
    if high_risk_arns:
        lines += [
            f"## High-risk principals ({len(high_risk_arns)})",
            "",
            "Principals with admin-equivalent grants, external/public access, or no MFA.",
            "",
        ]
        for arn in high_risk_arns:
            lines.append(f"- `{arn}`")
        lines.append("")

    # Per-severity sections.
    lines += ["## Findings", ""]
    by_sev: dict[Severity, list[IdentityFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            principal_summary = ", ".join(f.principal_arns) or "(no principal)"
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Type: {f.finding_type.value}; Principals: {principal_summary}"
            )
        lines.append("")

    return "\n".join(lines)


def _high_risk_principal_arns(findings: list[IdentityFinding]) -> list[str]:
    """Dedup principal ARNs that appear in any high-risk finding type, preserving order."""
    seen: dict[str, None] = {}
    for f in findings:
        if f.finding_type not in _HIGH_RISK_TYPES:
            continue
        for arn in f.principal_arns:
            if arn and arn not in seen:
                seen[arn] = None
    return list(seen)


__all__ = ["render_summary"]
