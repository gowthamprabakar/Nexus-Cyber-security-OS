"""Render a Kubernetes Posture `FindingsReport` as operator-readable markdown.

Two structural pins (per the D.6 plan):

1. **Per-namespace breakdown** — pinned ABOVE the per-severity sections.
   K8s operators triage namespace-by-namespace; the headline shows the
   namespace surface before drilling into severity.
2. **CRITICAL findings** — every CRITICAL finding regardless of namespace,
   pinned above the per-severity drilldown. Mirrors F.3 + D.3 + D.4 +
   D.5 patterns.

Layout:

1. Header + metadata
2. Per-namespace breakdown (counts per namespace, with per-source split)
3. Severity breakdown (counts across CRITICAL → INFO)
4. Source-type breakdown (counts per `K8sFindingType` — CIS / Polaris / Manifest)
5. **CRITICAL findings** (pinned, when any exist)
6. Per-severity sections (Critical → Info), each lists findings

Uses F.3's re-exported `CloudPostureFinding` + `FindingsReport` shape.
"""

from __future__ import annotations

from typing import Any

from k8s_posture.schemas import (
    CloudPostureFinding,
    FindingsReport,
    K8sFindingType,
    Severity,
)

_HEADER = "# Kubernetes Posture Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_SOURCE_ORDER: tuple[K8sFindingType, ...] = (
    K8sFindingType.CIS,
    K8sFindingType.POLARIS,
    K8sFindingType.MANIFEST,
)


def render_summary(report: FindingsReport) -> str:
    """Render a Kubernetes Posture `FindingsReport` to operator-facing markdown."""
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
            "No Kubernetes posture findings in this scan window.",
        ]
        return "\n".join(lines)

    findings = [CloudPostureFinding(raw) for raw in report.findings]
    source_counts = _count_by_source(report)
    namespace_counts = _count_by_namespace(findings)

    # Pinned: per-namespace breakdown.
    lines += [
        "## Per-namespace breakdown",
        "",
    ]
    for namespace in sorted(namespace_counts):
        per_source = namespace_counts[namespace]
        total = sum(per_source.values())
        cis = per_source.get(K8sFindingType.CIS.value, 0)
        pol = per_source.get(K8sFindingType.POLARIS.value, 0)
        man = per_source.get(K8sFindingType.MANIFEST.value, 0)
        lines.append(f"- **{namespace}**: {total} (CIS: {cis} | Polaris: {pol} | Manifest: {man})")
    lines.append("")

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
            namespace, source = _namespace_and_source(f)
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n  Namespace: {namespace}; Source: {source}"
            )
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
            namespace, source = _namespace_and_source(f)
            res_summary = _resource_summary(f)
            lines.append(
                f"- `{f.finding_id}` — {f.title}  \n"
                f"  Namespace: {namespace}; Source: {source}; Resource: {res_summary}"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------- helpers ------------------------------------


def _count_by_source(report: FindingsReport) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys((s.value for s in _SOURCE_ORDER), 0)
    for raw in report.findings:
        evs = raw.get("evidences") or []
        for ev in evs:
            if isinstance(ev, dict):
                source = str(ev.get("source_finding_type", ""))
                if source in counts:
                    counts[source] += 1
                    break  # only the first source-bearing evidence counts
    return counts


def _count_by_namespace(
    findings: list[CloudPostureFinding],
) -> dict[str, dict[str, int]]:
    """Roll findings into `{namespace: {source: count}}`."""
    out: dict[str, dict[str, int]] = {}
    for f in findings:
        namespace, source = _namespace_and_source(f)
        bucket = out.setdefault(namespace, dict.fromkeys((s.value for s in _SOURCE_ORDER), 0))
        if source in bucket:
            bucket[source] += 1
    return out


def _namespace_and_source(f: CloudPostureFinding) -> tuple[str, str]:
    """Pull `(namespace, source)` from the finding's resources + evidence."""
    payload = f.to_dict()
    resources = payload.get("resources") or []
    first = resources[0] if resources and isinstance(resources[0], dict) else {}
    namespace = str(first.get("owner", {}).get("account_uid", "")) or "unknown"
    evs = payload.get("evidences") or []
    source = ""
    for ev in evs:
        if isinstance(ev, dict):
            src = str(ev.get("source_finding_type", ""))
            if src:
                source = src
                break
    return namespace, source or "unknown"


def _resource_summary(f: CloudPostureFinding) -> str:
    resources: list[dict[str, Any]] = f.to_dict().get("resources", []) or []
    if not resources:
        return "(no resource)"
    first = resources[0]
    return str(first.get("uid", "")) or "(no id)"


__all__ = ["render_summary"]
