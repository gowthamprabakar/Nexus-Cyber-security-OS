"""Render a Multi-Cloud Posture `FindingsReport` as operator-readable markdown.

Two structural pins (per the D.5 plan):

1. **Per-cloud breakdown** — pinned ABOVE the per-severity sections.
   Operators want a one-glance Azure vs GCP split before drilling down.
2. **CRITICAL findings** — every CRITICAL finding regardless of cloud,
   pinned above the per-severity-section drilldown. Mirrors F.3 + D.3 +
   D.4 patterns.

Layout:

1. Header + metadata
2. Per-cloud breakdown (Azure: defender + activity counts; GCP: scc + iam counts) — pinned
3. Severity breakdown (counts across CRITICAL → INFO)
4. Source-type breakdown (counts per `CSPMFindingType`)
5. **CRITICAL findings** (pinned, when any exist)
6. Per-severity sections (Critical → Info), each lists findings

Uses F.3's re-exported `CloudPostureFinding` + `FindingsReport` shape.
"""

from __future__ import annotations

from typing import Any

from multi_cloud_posture.schemas import (
    CloudPostureFinding,
    CSPMFindingType,
    FindingsReport,
    Severity,
    cloud_provider_for,
)

_HEADER = "# Multi-Cloud Posture Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_SOURCE_ORDER: tuple[CSPMFindingType, ...] = (
    CSPMFindingType.AZURE_DEFENDER,
    CSPMFindingType.AZURE_ACTIVITY,
    CSPMFindingType.GCP_SCC,
    CSPMFindingType.GCP_IAM,
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
            "No multi-cloud posture findings in this scan window.",
        ]
        return "\n".join(lines)

    findings = [CloudPostureFinding(raw) for raw in report.findings]
    source_counts = _count_by_source(report)
    cloud_counts = _count_by_cloud(source_counts)

    # Pinned: per-cloud breakdown.
    lines += [
        "## Per-cloud breakdown",
        "",
        f"- **Azure**: {cloud_counts['azure']} "
        f"(Defender: {source_counts.get(CSPMFindingType.AZURE_DEFENDER.value, 0)} | "
        f"Activity: {source_counts.get(CSPMFindingType.AZURE_ACTIVITY.value, 0)})",
        f"- **GCP**:   {cloud_counts['gcp']} "
        f"(SCC: {source_counts.get(CSPMFindingType.GCP_SCC.value, 0)} | "
        f"IAM: {source_counts.get(CSPMFindingType.GCP_IAM.value, 0)})",
        "",
    ]

    # Severity breakdown.
    sev_counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {sev_counts.get(sev.value, 0)}")
    lines.append("")

    # Source-type breakdown.
    lines += ["## Source-type breakdown", ""]
    for src in _SOURCE_ORDER:
        lines.append(f"- **{src.value}**: {source_counts.get(src.value, 0)}")
    lines.append("")

    # Pinned: CRITICAL findings.
    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    if critical:
        lines += [
            f"## Critical findings ({len(critical)})",
            "",
            "Drop-everything issues — investigate before any per-severity section.",
            "",
        ]
        for f in critical:
            cloud, source = _cloud_and_source(f)
            lines.append(f"- `{f.finding_id}` — {f.title}  \n  Cloud: {cloud}; Source: {source}")
        lines.append("")

    # Per-severity sections.
    lines += ["## Findings", ""]
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
            cloud, source = _cloud_and_source(f)
            res_summary = _resource_summary(f)
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Cloud: {cloud}; Source: {source}; Resource: {res_summary}"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------- helpers ------------------------------------


def _count_by_source(report: FindingsReport) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys((s.value for s in _SOURCE_ORDER), 0)
    for raw in report.findings:
        ev = (raw.get("evidences") or [{}])[0] if raw.get("evidences") else {}
        if isinstance(ev, dict):
            source = str(ev.get("source_finding_type", ""))
            if source in counts:
                counts[source] += 1
    return counts


def _count_by_cloud(source_counts: dict[str, int]) -> dict[str, int]:
    """Roll up source counts into per-cloud totals."""
    out = {"azure": 0, "gcp": 0}
    for source_str, count in source_counts.items():
        try:
            ft = CSPMFindingType(source_str)
        except ValueError:
            continue
        provider = cloud_provider_for(ft)
        out[provider.value] += count
    return out


def _cloud_and_source(f: CloudPostureFinding) -> tuple[str, str]:
    """Pull `(cloud, source)` from the finding's evidence."""
    evs = f.to_dict().get("evidences") or []
    ev = evs[0] if evs and isinstance(evs[0], dict) else {}
    source_str = str(ev.get("source_finding_type", ""))
    try:
        ft = CSPMFindingType(source_str)
        return cloud_provider_for(ft).value, source_str
    except ValueError:
        return "unknown", source_str or "unknown"


def _resource_summary(f: CloudPostureFinding) -> str:
    resources: list[dict[str, Any]] = f.to_dict().get("resources", []) or []
    if not resources:
        return "(no resource)"
    first = resources[0]
    rid = str(first.get("uid", ""))
    # Trim long Azure/GCP resource IDs to last 2 segments for readability.
    parts = [p for p in rid.split("/") if p]
    if len(parts) >= 2:
        return ".../" + "/".join(parts[-2:])
    return rid or "(no id)"


__all__ = ["render_summary"]
