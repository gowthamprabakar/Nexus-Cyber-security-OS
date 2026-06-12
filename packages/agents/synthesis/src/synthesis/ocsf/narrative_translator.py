"""Narrative-to-OCSF translator (synthesis v0.2 Task 3, Q1/WI-Y12).

Converts the assembled ``SynthesisReport`` (the 3-call LLM pipeline output) into an OCSF 2004
Detection Finding via the Task-2 schema. The markdown narrative (heading + body per section, in
order) + executive summary ride in the unmapped slot; the cited finding ids become the source
set. The report still serializes to its two markdown files (WI-Y12) — this translation is
**additive**. Pure + deterministic (WI-Y5).
"""

from __future__ import annotations

from typing import Any

from synthesis.ocsf.schema import build_synthesis_finding
from synthesis.schemas import SynthesisReport

_VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


def render_narrative_markdown(report: SynthesisReport) -> str:
    """The narrative as markdown — ``## heading`` + body per section, in order."""
    return "\n\n".join(f"## {s.heading}\n\n{s.body}" for s in report.sections)


def derive_severity(report: SynthesisReport) -> str:
    """The narrative's headline severity from the executive-summary key metrics, else medium."""
    metrics = report.executive_summary.key_metrics
    for key in ("highest_severity", "severity", "max_severity"):
        value = metrics.get(key)
        if isinstance(value, str) and value.lower() in _VALID_SEVERITIES:
            return value.lower()
    return "medium"


def translate_report_to_ocsf(
    report: SynthesisReport,
    *,
    finding_id: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """Render a ``SynthesisReport`` as an OCSF 2004 Detection Finding."""
    detected_at_ms = int(report.scan_completed_at.timestamp() * 1000)
    resolved_title = title or (
        report.sections[0].heading if report.sections else "Synthesis narrative"
    )
    return build_synthesis_finding(
        finding_id=finding_id or f"SYN-{report.run_id}",
        title=resolved_title,
        narrative_markdown=render_narrative_markdown(report),
        executive_summary=report.executive_summary.paragraph,
        severity=derive_severity(report),
        source_finding_ids=tuple(report.cited_finding_ids),
        detected_at_ms=detected_at_ms,
    )
