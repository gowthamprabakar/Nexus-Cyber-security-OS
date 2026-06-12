"""synthesis v0.2 Task 7 — cross-source narrative orchestration tests (Q3/H3/WI-Y13)."""

from __future__ import annotations

from synthesis.cross_source import (
    cross_source_context,
    rank_sources_by_risk,
    summarize_source_risk,
)
from synthesis.tools.fleet_enumeration import enumerate_source
from synthesis.tools.fleet_workspace_reader import SOURCE_AGENTS, FleetFindings


def _f(uid: str, *, severity: str = "high") -> dict:
    return {"class_uid": 2004, "severity": severity, "finding_info": {"uid": uid}}


def _fleet(**by_agent) -> FleetFindings:
    base = dict.fromkeys(SOURCE_AGENTS, ())
    base.update(by_agent)
    return FleetFindings(by_agent=base)


def test_summarize_risk_weight() -> None:
    e = enumerate_source("compliance", (_f("C-1", severity="critical"), _f("C-2", severity="low")))
    s = summarize_source_risk(e)
    assert s.severity_weight == 5 + 2 and s.finding_count == 2


def test_rank_by_risk_desc() -> None:
    fleet = _fleet(
        compliance=(_f("C-1", severity="low"),),
        audit=(_f("A-1", severity="critical"), _f("A-2", severity="critical")),
    )
    ranked = rank_sources_by_risk(fleet)
    assert [s.agent_id for s in ranked] == ["audit", "compliance"]  # higher risk first


def test_rank_excludes_empty_sources() -> None:
    fleet = _fleet(compliance=(_f("C-1"),))
    ranked = rank_sources_by_risk(fleet)
    assert [s.agent_id for s in ranked] == ["compliance"]


def test_cross_source_context_structure() -> None:
    fleet = _fleet(compliance=(_f("C-1"),), audit=(_f("A-1"),))
    ctx = cross_source_context(fleet)
    assert ctx["sources_with_findings"] == 2 and ctx["total_findings"] == 2
    assert {r["agent"] for r in ctx["ranked_sources"]} == {"compliance", "audit"}


def test_context_carries_source_id_set_for_guard() -> None:
    # WI-Y13: the source finding-id set the hallucination guard checks against.
    fleet = _fleet(compliance=(_f("C-1"), _f("C-2")), audit=(_f("A-1"),))
    ctx = cross_source_context(fleet)
    assert ctx["source_finding_id_set"] == ["A-1", "C-1", "C-2"]


def test_h3_risk_quantified() -> None:
    # H3: each ranked source carries a quantified risk weight + count (risk, then evidence).
    fleet = _fleet(compliance=(_f("C-1", severity="high"),))
    [src] = cross_source_context(fleet)["ranked_sources"]
    assert src["risk_weight"] == 4 and src["count"] == 1


def test_empty_fleet() -> None:
    ctx = cross_source_context(_fleet())
    assert ctx["sources_with_findings"] == 0 and ctx["source_finding_id_set"] == []
