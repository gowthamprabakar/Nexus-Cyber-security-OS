"""Briefing generator skeleton + API (D.8 v0.2 Task 12).

The operator-facing intelligence-briefing API. Per **Q5** v0.2 ships a **skeleton**:
it collects the relevant findings over a time range and renders a simple aggregated
markdown summary. Full content generation (LLM-narrated insights, ranked threat
analysis) is **v0.3**. Task 13 fleshes out the template sections on top of this API.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

#: Severity ordering for the briefing breakdown (most → least severe).
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


@dataclass(frozen=True, slots=True)
class TimeRange:
    start: str  # ISO 8601
    end: str


@dataclass(frozen=True, slots=True)
class Briefing:
    customer_id: str
    time_range: TimeRange
    finding_count: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    markdown: str = ""


def generate_briefing(
    findings: Sequence[Mapping[str, Any]],
    *,
    customer_id: str,
    time_range: TimeRange,
    fmt: str = "markdown",
) -> Briefing:
    """Aggregate ``findings`` over ``time_range`` into an operator briefing.

    v0.2 skeleton: counts findings by severity and renders a markdown digest. ``fmt``
    accepts ``"markdown"`` only at v0.2.
    """
    if fmt != "markdown":
        raise ValueError(f"unsupported briefing format: {fmt!r} (v0.2 supports 'markdown')")

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "Unknown"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    markdown = _render_skeleton(customer_id, time_range, len(findings), severity_counts)
    return Briefing(
        customer_id=customer_id,
        time_range=time_range,
        finding_count=len(findings),
        severity_counts=severity_counts,
        markdown=markdown,
    )


def _render_skeleton(
    customer_id: str,
    time_range: TimeRange,
    total: int,
    severity_counts: Mapping[str, int],
) -> str:
    lines = [
        f"# Threat Intelligence Briefing — {customer_id}",
        "",
        f"**Window:** {time_range.start} → {time_range.end}",
        f"**Total findings:** {total}",
        "",
        "## Severity breakdown",
        "",
    ]
    ordered = [s for s in _SEVERITY_ORDER if s in severity_counts]
    ordered += sorted(s for s in severity_counts if s not in _SEVERITY_ORDER)
    if ordered:
        for sev in ordered:
            lines.append(f"- **{sev}**: {severity_counts[sev]}")
    else:
        lines.append("- _No findings in this window._")
    lines += [
        "",
        "## Key threats",
        "",
        "_v0.3: ranked threat-actor + campaign narrative._",
        "",
        "## Recommendations",
        "",
        "_v0.3: prioritized, tech-stack-aware actions._",
        "",
    ]
    return "\n".join(lines)
