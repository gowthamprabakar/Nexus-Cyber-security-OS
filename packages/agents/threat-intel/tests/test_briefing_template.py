"""D.8 v0.2 Task 13 — briefing template + sectioning tests."""

from __future__ import annotations

from threat_intel.briefing.generator import TimeRange
from threat_intel.briefing.template import (
    BriefingContext,
    executive_summary_section,
    filter_findings_by_time,
    iocs_section,
    key_threats_section,
    recommendations_section,
    render_briefing,
)
from threat_intel.customer.industry_profile import IndustryProfile
from threat_intel.customer.tech_stack_profile import TechStackProfile

_TR = TimeRange(start="2026-06-01T00:00:00Z", end="2026-06-10T00:00:00Z")
_FINDINGS = (
    {"severity": "High", "title": "IOC match", "time": "2026-06-05T00:00:00Z", "iocs": ["1.2.3.4"]},
    {
        "severity": "Critical",
        "title": "KEV match",
        "time": "2026-06-06T00:00:00Z",
        "iocs": ["evil.example", "1.2.3.4"],
    },
)


def _ctx(**kw: object) -> BriefingContext:
    base: dict[str, object] = {"findings": _FINDINGS, "customer_id": "cust_x", "time_range": _TR}
    base.update(kw)
    return BriefingContext(**base)  # type: ignore[arg-type]


def test_render_includes_all_four_sections() -> None:
    md = render_briefing(_ctx())
    for heading in (
        "Executive summary",
        "Key threats",
        "Indicators of compromise",
        "Recommendations",
    ):
        assert f"## {heading}" in md
    assert "# Threat Intelligence Briefing — cust_x" in md


def test_executive_summary_counts_and_vertical() -> None:
    md = executive_summary_section(_ctx(industry=IndustryProfile("technology", "technology", ())))
    assert "2 findings for **cust_x** (technology)" in md
    assert "1 critical, 1 high" in md


def test_key_threats_ordered_critical_first() -> None:
    md = key_threats_section(_ctx())
    assert md.index("KEV match") < md.index("IOC match")  # Critical before High


def test_iocs_deduplicated() -> None:
    md = iocs_section(_ctx())
    assert md.count("1.2.3.4") == 1  # appears in both findings, listed once
    assert "evil.example" in md


def test_recommendations_tech_stack_aware() -> None:
    md = recommendations_section(_ctx(tech_stack=TechStackProfile(languages=("python",))))
    assert "Prioritize findings affecting the customer stack: python." in md


def test_recommendations_placeholder_without_tech_stack() -> None:
    assert "v0.3" in recommendations_section(_ctx())


def test_filter_findings_by_time() -> None:
    findings = [
        {"title": "in", "time": "2026-06-05T00:00:00Z"},
        {"title": "out", "time": "2026-07-01T00:00:00Z"},
        {"title": "nodate"},
    ]
    kept = filter_findings_by_time(findings, _TR)
    titles = {f["title"] for f in kept}
    assert titles == {"in", "nodate"}  # out-of-window dropped; missing-time kept


def test_pluggable_section_list() -> None:
    md = render_briefing(_ctx(), sections=(recommendations_section,))
    assert "## Recommendations" in md and "## Key threats" not in md


def test_empty_findings_sections_valid() -> None:
    md = render_briefing(_ctx(findings=()))
    assert "_No threats in this window._" in md
    assert "_No IOCs extracted in this window._" in md
