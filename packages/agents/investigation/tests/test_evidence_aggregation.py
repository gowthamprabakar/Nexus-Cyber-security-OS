"""investigation v0.2 Task 3 — multi-source evidence aggregation tests (Q2)."""

from __future__ import annotations

from investigation.tools.evidence_aggregation import (
    aggregate_fleet,
    all_evidence_ids,
    cross_agent_duplicates,
    deduplicate_findings,
    enumerate_source,
)
from investigation.tools.fleet_evidence_reader import SOURCE_AGENTS, FleetEvidence
from investigation.tools.related_findings import RelatedFinding


def _rf(agent: str, uid: str, *, class_uid: int = 2004) -> RelatedFinding:
    return RelatedFinding(
        source_agent=agent,
        source_run_id="r1",
        class_uid=class_uid,
        payload={"class_uid": class_uid, "finding_info": {"uid": uid}},
    )


def _evidence(**by_agent) -> FleetEvidence:
    base = dict.fromkeys(SOURCE_AGENTS, ())
    base.update(by_agent)
    return FleetEvidence(tenant_id="t1", by_agent=base)


def test_enumerate_source() -> None:
    e = enumerate_source(
        "compliance", (_rf("compliance", "C-1"), _rf("compliance", "C-2", class_uid=2003))
    )
    assert e.finding_count == 2 and e.by_class_uid == {2004: 1, 2003: 1}
    assert e.finding_ids == ("C-1", "C-2")


def test_aggregate_fleet_one_per_source() -> None:
    result = aggregate_fleet(_evidence(audit=(_rf("audit", "A-1"),)))
    assert len(result) == 13
    assert {e.agent_id for e in result} == set(SOURCE_AGENTS)


def test_deduplicate_findings() -> None:
    # same uid reported by 2 agents.
    ev = _evidence(compliance=(_rf("compliance", "INC-1"),), audit=(_rf("audit", "INC-1"),))
    dedup = deduplicate_findings(ev)
    assert dedup["INC-1"] == ("audit", "compliance")


def test_cross_agent_duplicates_only() -> None:
    ev = _evidence(
        compliance=(_rf("compliance", "INC-1"), _rf("compliance", "C-only")),
        audit=(_rf("audit", "INC-1"),),
    )
    dups = cross_agent_duplicates(ev)
    assert set(dups) == {"INC-1"} and "C-only" not in dups


def test_all_evidence_ids() -> None:
    ev = _evidence(compliance=(_rf("compliance", "C-1"),), audit=(_rf("audit", "A-1"),))
    assert all_evidence_ids(ev) == {"finding:C-1", "finding:A-1"}


def test_empty_evidence() -> None:
    ev = _evidence()
    assert deduplicate_findings(ev) == {} and all_evidence_ids(ev) == set()
