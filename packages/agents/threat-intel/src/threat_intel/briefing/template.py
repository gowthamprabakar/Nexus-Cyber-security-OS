"""Briefing template + pluggable section generators (D.8 v0.2 Task 13).

Builds on the Task-12 skeleton: a structured briefing of four sections (executive
summary, key threats, IOCs, recommendations), each produced by a **pluggable** section
generator over a `BriefingContext`. Time-range filtering + customer-context awareness
(industry / tech-stack profiles) feed the sections. Per **Q5** the section bodies stay
skeleton-level (structured aggregation, no LLM narration) — full content is v0.3.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from threat_intel.briefing.generator import _SEVERITY_ORDER, TimeRange
from threat_intel.customer.industry_profile import IndustryProfile
from threat_intel.customer.tech_stack_profile import TechStackProfile


@dataclass(frozen=True, slots=True)
class BriefingContext:
    findings: tuple[Mapping[str, Any], ...]
    customer_id: str
    time_range: TimeRange
    industry: IndustryProfile | None = None
    tech_stack: TechStackProfile | None = None


#: A section generator maps a context → a markdown block.
SectionFn = Callable[[BriefingContext], str]


def _severity_rank(finding: Mapping[str, Any]) -> int:
    sev = str(finding.get("severity", "Unknown"))
    return _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def filter_findings_by_time(
    findings: Sequence[Mapping[str, Any]], time_range: TimeRange, *, time_key: str = "time"
) -> tuple[Mapping[str, Any], ...]:
    """Keep findings whose ``time_key`` (ISO 8601) falls within ``[start, end]``.
    Findings without the key are kept (cannot be excluded on missing data)."""
    out: list[Mapping[str, Any]] = []
    for f in findings:
        ts = f.get(time_key)
        if ts is None or time_range.start <= str(ts) <= time_range.end:
            out.append(f)
    return tuple(out)


def executive_summary_section(ctx: BriefingContext) -> str:
    crit = sum(1 for f in ctx.findings if f.get("severity") == "Critical")
    high = sum(1 for f in ctx.findings if f.get("severity") == "High")
    vertical = f" ({ctx.industry.vertical})" if ctx.industry else ""
    return "\n".join(
        [
            "## Executive summary",
            "",
            f"{len(ctx.findings)} findings for **{ctx.customer_id}**{vertical} over "
            f"{ctx.time_range.start} → {ctx.time_range.end}: "
            f"{crit} critical, {high} high.",
        ]
    )


def key_threats_section(ctx: BriefingContext, *, top: int = 5) -> str:
    ranked = sorted(ctx.findings, key=_severity_rank)[:top]
    lines = ["## Key threats", ""]
    if ranked:
        for f in ranked:
            sev = str(f.get("severity", "Unknown"))
            title = str(f.get("title", f.get("finding_id", "(untitled)")))
            lines.append(f"- **{sev}** — {title}")
    else:
        lines.append("_No threats in this window._")
    return "\n".join(lines)


def iocs_section(ctx: BriefingContext) -> str:
    values: list[str] = []
    seen: set[str] = set()
    for f in ctx.findings:
        for ioc in f.get("iocs", []) if isinstance(f.get("iocs"), list) else []:
            v = str(ioc)
            if v and v not in seen:
                seen.add(v)
                values.append(v)
    lines = ["## Indicators of compromise", ""]
    lines += [f"- `{v}`" for v in values] if values else ["_No IOCs extracted in this window._"]
    return "\n".join(lines)


def recommendations_section(ctx: BriefingContext) -> str:
    lines = ["## Recommendations", ""]
    if ctx.tech_stack and ctx.tech_stack.keywords:
        kws = ", ".join(sorted(ctx.tech_stack.keywords))
        lines.append(f"Prioritize findings affecting the customer stack: {kws}.")
    else:
        lines.append("_v0.3: prioritized, tech-stack-aware actions._")
    return "\n".join(lines)


DEFAULT_SECTIONS: tuple[SectionFn, ...] = (
    executive_summary_section,
    key_threats_section,
    iocs_section,
    recommendations_section,
)


def render_briefing(
    ctx: BriefingContext, *, sections: Sequence[SectionFn] = DEFAULT_SECTIONS
) -> str:
    """Render the full briefing markdown from a pluggable list of section generators."""
    title = f"# Threat Intelligence Briefing — {ctx.customer_id}"
    return "\n\n".join([title, *(section(ctx) for section in sections)])
