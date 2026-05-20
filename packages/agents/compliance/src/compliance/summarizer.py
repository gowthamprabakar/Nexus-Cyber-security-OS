"""Render a Compliance ``FindingsReport`` as operator-readable markdown.

Stage-6 SUMMARIZE per the D.6 v0.1 plan. Deterministic, no LLM in
loop -- the agent driver (Task 11) writes the rendered string to
``report.md`` in the charter workspace.

Layout (top to bottom):

  1. Header + metadata (customer, run_id, scan window, total
     failures).
  2. **Posture summary** (counts by CIS Level + total
     covered/failed; high-level table).
  3. **Severity breakdown** (CRITICAL → INFO).
  4. **Finding-type breakdown** (per CIS control id with at least
     one failure).
  5. **CIS Level-1 failures (pinned)** — highest priority; Level-1
     controls are minimum-required posture. Pinned above per-
     severity sections so operators see them first; mirrors
     D.4's pinned-beacons + D.8's pinned-KEV pattern.
  6. **Per-severity sections** (CRITICAL → LOW), all failing
     controls.
  7. **Attribution footer** (Q6 license; **always emitted**) —
     CIS Benchmarks® + paraphrase notice + canonical-source URL.

Q6 reminder: this summary contains paraphrased control names +
public control IDs only. No verbatim CIS Securesuite text; no PII;
no classifier-matched substrings inherited from D.5.
"""

from __future__ import annotations

from typing import Any

from compliance.schemas import (
    ComplianceFinding,
    FindingsReport,
    Severity,
)

_HEADER = "# Compliance Posture — CIS AWS Foundations Benchmark v3.0"

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

# Attribution footer. Required by Q6 of the D.6 plan — CIS Benchmarks®
# is governed by the CIS Securesuite licence; redistribution of
# verbatim text is restricted. v0.1 ships paraphrased control names +
# public control IDs only; the footer points operators to the
# canonical CIS source for the full benchmark text.
_ATTRIBUTION_FOOTER = (
    "---\n\n"
    "## Attribution\n\n"
    "Compliance control taxonomy derived from:\n\n"
    "- **CIS Benchmarks®** — © Center for Internet Security, Inc. "
    "https://www.cisecurity.org/cis-benchmarks/\n\n"
    "This report carries paraphrased operator-facing summaries of the CIS "
    "control structure (control IDs + level + applicability are public "
    "reference metadata; descriptions are written in-house). "
    "No verbatim CIS Securesuite text is reproduced here. "
    "Refer to the canonical CIS publication for the full benchmark text "
    "and audit/remediation procedures."
)


def render_summary(report: FindingsReport) -> str:
    """Render the full markdown report for a D.6 ``FindingsReport``."""
    lines: list[str] = [
        _HEADER,
        "",
        f"- Customer: `{report.customer_id}`",
        f"- Run ID: `{report.run_id}`",
        (
            f"- Scan window: {report.scan_started_at.isoformat()} -> "
            f"{report.scan_completed_at.isoformat()}"
        ),
        f"- Failing controls: **{report.total}**",
        "",
    ]

    if report.total == 0:
        lines += [
            "## Summary",
            "",
            "No CIS controls failed in this scan window. (Note: v0.1 "
            "emits FAIL-only output; controls with no contributing "
            "source-findings or only LOW-severity contributors are "
            "omitted.)",
            "",
            _ATTRIBUTION_FOOTER,
        ]
        return "\n".join(lines)

    findings = [ComplianceFinding(raw) for raw in report.findings]

    # Posture summary table.
    level_1_failures = _count_failures_by_level(findings, level_label="level_1")
    level_2_failures = _count_failures_by_level(findings, level_label="level_2")
    lines += [
        "## Posture summary",
        "",
        "| Bucket | Failing controls |",
        "| --- | --- |",
        f"| CIS Level 1 (minimum-required) | {level_1_failures} |",
        f"| CIS Level 2 (defense-in-depth) | {level_2_failures} |",
        f"| **Total** | **{report.total}** |",
        "",
    ]

    # Severity breakdown.
    sev_counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {sev_counts.get(sev.value, 0)}")
    lines.append("")

    # Finding-type breakdown (per CIS control id).
    type_counts = _count_by_control_id(findings)
    lines += ["## Failing controls", ""]
    for control_id in sorted(type_counts.keys()):
        lines.append(f"- **{control_id}**: {type_counts[control_id]}")
    lines.append("")

    # Pinned: CIS Level-1 failures (most operationally urgent).
    level_1_findings = [f for f in findings if _control_level(f) == "level_1"]
    if level_1_findings:
        lines += [
            f"## CIS Level 1 failures ({len(level_1_findings)})",
            "",
            "Level-1 controls are minimum-required posture. These "
            "failures are the highest-priority operational items.",
            "",
        ]
        for f in level_1_findings:
            control_id = _control_id(f)
            contrib_count = _contributor_count(f)
            lines.append(
                f"- `{f.finding_id}` -- **{f.severity.value.upper()}** "
                f"CIS {control_id}: {f.title}  \n"
                f"  -> {contrib_count} contributing source-finding(s)"
            )
        lines.append("")

    # Per-severity sections.
    lines += ["## Findings", ""]
    by_sev: dict[Severity, list[ComplianceFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            control_id = _control_id(f)
            lines.append(f"- `{f.finding_id}` -- CIS {control_id}: {f.title}")
        lines.append("")

    lines.append(_ATTRIBUTION_FOOTER)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_evidence(f: ComplianceFinding) -> dict[str, Any]:
    evs = f.to_dict().get("evidences") or []
    if isinstance(evs, list) and evs and isinstance(evs[0], dict):
        return dict(evs[0])
    return {}


def _control_id(f: ComplianceFinding) -> str:
    """Return the CIS control id from evidence (e.g. ``"1.10"``)."""
    ev = _first_evidence(f)
    control = ev.get("control")
    if isinstance(control, dict):
        cid = control.get("control_id")
        if isinstance(cid, str):
            return cid
    # Fallback: parse from rule_id (`cis_aws_v3:1.10` -> `1.10`).
    _, _, fallback = f.rule_id.partition(":")
    return fallback or "?"


def _control_level(f: ComplianceFinding) -> str:
    ev = _first_evidence(f)
    control = ev.get("control")
    if isinstance(control, dict):
        level = control.get("level")
        if isinstance(level, str):
            return level
    return ""


def _contributor_count(f: ComplianceFinding) -> int:
    ev = _first_evidence(f)
    count = ev.get("contributor_count")
    if isinstance(count, int):
        return count
    return 1


def _count_failures_by_level(findings: list[ComplianceFinding], *, level_label: str) -> int:
    return sum(1 for f in findings if _control_level(f) == level_label)


def _count_by_control_id(findings: list[ComplianceFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        cid = _control_id(f)
        counts[cid] = counts.get(cid, 0) + 1
    return counts


__all__ = ["render_summary"]
