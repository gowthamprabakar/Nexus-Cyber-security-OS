"""Render a Threat Intel ``FindingsReport`` as operator-readable markdown.

Stage-5 SUMMARIZE per the D.8 v0.1 plan. Deterministic, no LLM in
loop -- the agent driver (Task 12) writes the rendered string to
``report.md`` in the charter workspace.

Layout (top to bottom):

  1. Header + metadata (customer, run_id, scan window, total).
  2. **Severity breakdown** (CRITICAL → INFO).
  3. **Finding-type breakdown** (CVE_KEV / IOC_NET / IOC_RUN /
     TECHNIQUE).
  4. **CVE-in-KEV section (pinned)** — KEV-listed CVEs are CRITICAL
     operational items. Pinned above per-severity sections so
     operators see them first; mirrors D.4's "pinned beacons / DGAs"
     pattern.
  5. **IOC matches section** — network + runtime IOC hits, by IOC
     kind.
  6. **Per-severity sections** (CRITICAL → LOW), all findings.
  7. **Attribution footer** (Q6 license; **always emitted**) — MITRE
     ATT&CK CC-BY-4.0 + NVD (public domain) + CISA KEV (CC0). The
     footer is required even when ``report.total == 0`` because the
     agent may still have consulted the feeds in Stage-2 ENRICH.

Q6 reminder: this summary contains feed-derived metadata only -- CVE
IDs, IOC values from public threat feeds, ATT&CK technique IDs. No
PII; no classifier-matched substrings.
"""

from __future__ import annotations

from typing import Any

from threat_intel.schemas import (
    FindingsReport,
    Severity,
    ThreatIntelFinding,
    ThreatIntelFindingType,
)

_HEADER = "# Threat Intel Scan"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_FINDING_TYPE_ORDER: tuple[ThreatIntelFindingType, ...] = (
    ThreatIntelFindingType.CVE_IN_KEV_CATALOG,
    ThreatIntelFindingType.IOC_MATCH_NETWORK,
    ThreatIntelFindingType.IOC_MATCH_RUNTIME,
    ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED,
)

# Attribution footer. Required by Q6 of the D.8 plan — MITRE ATT&CK is
# CC-BY-4.0 and the licence stipulates attribution on derivative works.
# NVD and CISA KEV are public-domain / CC0 (no attribution required)
# but called out for transparency.
_ATTRIBUTION_FOOTER = (
    "---\n\n"
    "## Attribution\n\n"
    "Threat-intel context derived from:\n\n"
    "- **MITRE ATT&CK®** (Creative Commons Attribution 4.0 International, "
    "CC-BY-4.0) -- https://attack.mitre.org/.\n"
    "- **NVD** (National Vulnerability Database, public domain) -- "
    "https://nvd.nist.gov/.\n"
    "- **CISA KEV** (Known Exploited Vulnerabilities catalogue, CC0) -- "
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog."
)


def render_summary(report: FindingsReport) -> str:
    """Render the full markdown report for a D.8 ``FindingsReport``."""
    lines: list[str] = [
        _HEADER,
        "",
        f"- Customer: `{report.customer_id}`",
        f"- Run ID: `{report.run_id}`",
        (
            f"- Scan window: {report.scan_started_at.isoformat()} -> "
            f"{report.scan_completed_at.isoformat()}"
        ),
        f"- Total findings: **{report.total}**",
        "",
    ]

    if report.total == 0:
        lines += [
            "## Summary",
            "",
            "No threat-intel correlations produced findings in this scan window.",
            "",
            _ATTRIBUTION_FOOTER,
        ]
        return "\n".join(lines)

    findings = [ThreatIntelFinding(raw) for raw in report.findings]

    # Severity breakdown.
    sev_counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {sev_counts.get(sev.value, 0)}")
    lines.append("")

    # Finding-type breakdown.
    type_counts = _count_by_finding_type(findings)
    lines += ["## Finding-type breakdown", ""]
    for ft in _FINDING_TYPE_ORDER:
        lines.append(f"- **{ft.value}**: {type_counts.get(ft, 0)}")
    lines.append("")

    # Pinned: CVE-in-KEV (most operationally urgent).
    cve_kev = [
        f for f in findings if _finding_type_of(f) is ThreatIntelFindingType.CVE_IN_KEV_CATALOG
    ]
    if cve_kev:
        lines += [
            f"## CVE in CISA KEV ({len(cve_kev)})",
            "",
            "Vulnerabilities listed in the CISA Known-Exploited-Vulnerabilities "
            "catalog -- actively exploited in the wild. Operator action required.",
            "",
        ]
        for f in cve_kev:
            ev = _first_evidence(f)
            kev_entry = ev.get("kev_entry", {}) if isinstance(ev, dict) else {}
            cve_id = kev_entry.get("cve_id", "?")
            vendor = kev_entry.get("vendor_project", "?")
            product = kev_entry.get("product", "?")
            due_date = kev_entry.get("due_date") or "not set"
            ransomware = kev_entry.get("known_ransomware_campaign_use", False)
            ransomware_marker = " (ransomware-linked)" if ransomware else ""
            lines.append(
                f"- `{f.finding_id}` -- **{f.severity.value.upper()}** "
                f"{cve_id}{ransomware_marker}  \n"
                f"  -> {vendor} / {product} · CISA due date {due_date}"
            )
        lines.append("")

    # IOC matches section (network + runtime).
    ioc_findings = [
        f
        for f in findings
        if _finding_type_of(f)
        in (
            ThreatIntelFindingType.IOC_MATCH_NETWORK,
            ThreatIntelFindingType.IOC_MATCH_RUNTIME,
        )
    ]
    if ioc_findings:
        lines += [
            f"## IOC matches ({len(ioc_findings)})",
            "",
            "Public-feed IOCs observed in sibling-agent evidence (D.4 Network / D.3 Runtime).",
            "",
        ]
        for f in ioc_findings:
            ev = _first_evidence(f)
            ioc_entry = ev.get("ioc_entry", {}) if isinstance(ev, dict) else {}
            ioc_type = ioc_entry.get("ioc_type", "?")
            value = ioc_entry.get("value", "?")
            source_feed = ioc_entry.get("source_feed", "?")
            confidence = ioc_entry.get("confidence", "?")
            kind = (
                "network"
                if _finding_type_of(f) is ThreatIntelFindingType.IOC_MATCH_NETWORK
                else "runtime"
            )
            lines.append(
                f"- `{f.finding_id}` -- **{f.severity.value.upper()}** "
                f"{ioc_type}=`{value}` (in {kind})  \n"
                f"  -> feed `{source_feed}` · confidence {confidence}"
            )
        lines.append("")

    # Per-severity sections.
    lines += ["## Findings", ""]
    by_sev: dict[Severity, list[ThreatIntelFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            entry_type = _finding_type_of(f)
            ft_label = entry_type.value if entry_type is not None else "unknown"
            lines.append(f"- `{f.finding_id}` -- {f.title}  \n  Type: {ft_label}")
        lines.append("")

    lines.append(_ATTRIBUTION_FOOTER)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_type_of(f: ThreatIntelFinding) -> ThreatIntelFindingType | None:
    raw = f.to_dict().get("finding_info", {}).get("types") or []
    if not isinstance(raw, list) or not raw or not isinstance(raw[0], str):
        return None
    try:
        return ThreatIntelFindingType(raw[0])
    except ValueError:
        return None


def _first_evidence(f: ThreatIntelFinding) -> dict[str, Any]:
    evs = f.to_dict().get("evidences") or []
    if isinstance(evs, list) and evs and isinstance(evs[0], dict):
        return dict(evs[0])
    return {}


def _count_by_finding_type(
    findings: list[ThreatIntelFinding],
) -> dict[ThreatIntelFindingType, int]:
    counts: dict[ThreatIntelFindingType, int] = dict.fromkeys(_FINDING_TYPE_ORDER, 0)
    for f in findings:
        ft = _finding_type_of(f)
        if ft is None:
            continue
        counts[ft] = counts.get(ft, 0) + 1
    return counts


__all__ = ["render_summary"]
