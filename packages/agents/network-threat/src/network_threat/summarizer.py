"""Render a Network Threat `FindingsReport` as operator-readable markdown.

Mirrors D.3's [`summarizer`](../../../runtime-threat/src/runtime_threat/summarizer.py)
shape with **two structural pins** (per the D.4 plan's "pinned
beacons/DGA above per-section" rule):

1. **Beacon alerts** — every BEACON finding regardless of severity.
   Beacons are deterministic high-fidelity signals (low CoV = real
   periodicity, not Suricata-rule false positives) and operators
   want them visible before any other section.
2. **DGA domains** — every DGA finding regardless of severity. Same
   rationale: a DGA-shaped query is a strong signal even at MEDIUM.

Layout:

1. Header + metadata
2. Severity breakdown (counts across CRITICAL → INFO)
3. Finding-type breakdown (counts across the 4 families)
4. **Beacon alerts** (pinned, when any exist)
5. **DGA domains** (pinned, when any exist)
6. Per-severity sections (Critical → Info)

Mirrors F.6's tamper-pin-above-per-action pattern + D.3's
critical-runtime-pin pattern.
"""

from __future__ import annotations

from network_threat.schemas import (
    FindingsReport,
    FindingType,
    NetworkFinding,
    Severity,
)

_HEADER = "# Network Threat Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_FINDING_TYPE_ORDER: tuple[FindingType, ...] = (
    FindingType.PORT_SCAN,
    FindingType.BEACON,
    FindingType.DGA,
    FindingType.SURICATA,
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
            "No network threats detected in this scan window.",
        ]
        return "\n".join(lines)

    findings = [NetworkFinding(raw) for raw in report.findings]

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

    # Pinned: beacon alerts (highest-fidelity deterministic signal).
    beacons = [f for f in findings if f.finding_type is FindingType.BEACON]
    if beacons:
        lines += [
            f"## Beacon alerts ({len(beacons)})",
            "",
            "Periodic-connection patterns — deterministic detector. Review before any per-severity section.",
            "",
        ]
        for f in beacons:
            ev = f.evidence
            dst = ev.get("dst_ip", "?")
            port = ev.get("dst_port", "?")
            count = ev.get("connection_count", "?")
            cov = ev.get("coefficient_of_variation", "?")
            lines.append(
                f"- `{f.finding_id}` — **{f.severity.value.upper()}** {f.title}  \n"
                f"  → `{dst}:{port}` · {count} hits · CoV {cov}"
            )
        lines.append("")

    # Pinned: DGA domains.
    dgas = [f for f in findings if f.finding_type is FindingType.DGA]
    if dgas:
        lines += [
            f"## DGA domains ({len(dgas)})",
            "",
            "Random-looking second-level labels — entropy + n-gram heuristic.",
            "",
        ]
        for f in dgas:
            ev = f.evidence
            qname = ev.get("query_name", "?")
            entropy = ev.get("entropy", "?")
            bigram = ev.get("bigram_score", "?")
            src_ip = ev.get("src_ip", "(unknown src)")
            lines.append(
                f"- `{f.finding_id}` — **{f.severity.value.upper()}** {qname}  \n"
                f"  → src `{src_ip}` · entropy {entropy} · bigram {bigram}"
            )
        lines.append("")

    # Per-severity sections (everything, no filter).
    lines += ["## Findings", ""]
    by_sev: dict[Severity, list[NetworkFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            src = ", ".join(f.src_ips) or "(no src)"
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Type: {f.finding_type.value}; Source(s): {src}"
            )
        lines.append("")

    return "\n".join(lines)


__all__ = ["render_summary"]
