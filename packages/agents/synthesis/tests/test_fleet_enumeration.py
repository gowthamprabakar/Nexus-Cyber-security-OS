"""synthesis v0.2 Task 6 — per-source finding enumeration tests (Q3/WI-Y1)."""

from __future__ import annotations

from synthesis.tools.fleet_enumeration import (
    all_cited_finding_ids,
    enumerate_fleet,
    enumerate_source,
)
from synthesis.tools.fleet_workspace_reader import SOURCE_AGENTS, FleetFindings


def _f(uid: str, *, class_uid: int = 2004, severity: str = "High") -> dict:
    return {"class_uid": class_uid, "severity": severity, "finding_info": {"uid": uid}}


def test_enumerate_source_counts() -> None:
    e = enumerate_source("compliance", (_f("C-1"), _f("C-2", severity="Low")))
    assert e.finding_count == 2
    assert e.by_class_uid == {2004: 2}
    assert e.by_severity == {"high": 1, "low": 1}
    assert e.finding_ids == ("C-1", "C-2")


def test_enumerate_empty_source() -> None:
    e = enumerate_source("audit", ())
    assert e.finding_count == 0 and e.finding_ids == ()


def test_finding_without_uid_skipped_from_ids() -> None:
    e = enumerate_source("audit", ({"class_uid": 2004, "severity": "High"},))
    assert e.finding_count == 1 and e.finding_ids == ()  # counted, but no id


def test_unknown_severity() -> None:
    e = enumerate_source("audit", ({"class_uid": 2004, "finding_info": {"uid": "A-1"}},))
    assert e.by_severity == {"unknown": 1}


def test_enumerate_fleet_one_entry_per_source() -> None:
    fleet = FleetFindings(by_agent=dict.fromkeys(SOURCE_AGENTS, ()))
    result = enumerate_fleet(fleet)
    assert len(result) == 12
    assert {e.agent_id for e in result} == set(SOURCE_AGENTS)


def test_per_source_not_aggregated() -> None:
    # WI-Y1: per-source counts, not a fleet total.
    fleet = FleetFindings(
        by_agent={
            **dict.fromkeys(SOURCE_AGENTS, ()),
            "compliance": (_f("C-1"),),
            "audit": (_f("A-1"),),
        }
    )
    by_agent = {e.agent_id: e.finding_count for e in enumerate_fleet(fleet)}
    assert by_agent["compliance"] == 1 and by_agent["audit"] == 1 and by_agent["identity"] == 0


def test_all_cited_finding_ids() -> None:
    fleet = FleetFindings(
        by_agent={
            **dict.fromkeys(SOURCE_AGENTS, ()),
            "compliance": (_f("C-1"), _f("C-2")),
            "audit": (_f("A-1"),),
        }
    )
    assert all_cited_finding_ids(fleet) == {"C-1", "C-2", "A-1"}
