"""investigation v0.2 Task 23 — cross-agent OCSF 2005 sweep + per-source coverage (WI-I3).

D.7 is the **sole** OCSF 2005 (Incident Finding) emitter in the fleet — it *consumes* the other
emitters' 2002/2003/2004/6003 findings and *produces* the single 2005 incident. This sweep
asserts (a) the 13 source agents are exactly the fleet's evidence producers, (b) per-source
enumeration is independent (never a fleet total), and (c) D.7's emitted class_uid is 2005.
"""

from __future__ import annotations

from investigation.schemas import OCSF_CLASS_UID
from investigation.tools.evidence_aggregation import (
    aggregate_fleet,
    all_evidence_ids,
    enumerate_source,
)
from investigation.tools.fleet_evidence_reader import SOURCE_AGENTS, FleetEvidence
from investigation.tools.related_findings import RelatedFinding

_TENANT = "01HV0T0000000000000000TENA"


def _rf(agent: str, uid: str, *, class_uid: int = 2004) -> RelatedFinding:
    return RelatedFinding(
        source_agent=agent,
        source_run_id="r1",
        class_uid=class_uid,
        payload={"finding_info": {"uid": uid}},
    )


def test_thirteen_source_agents() -> None:
    # The exact fleet of evidence producers D.7 consumes (WI-I3 — breadth, honestly scoped).
    assert len(SOURCE_AGENTS) == 13
    assert set(SOURCE_AGENTS) == {
        "cloud_posture",
        "multi_cloud_posture",
        "vulnerability",
        "identity",
        "threat_intel",
        "runtime_threat",
        "network_threat",
        "k8s_posture",
        "compliance",
        "data_security",
        "audit",
        "supervisor",
        "synthesis",
    }


def test_d7_is_sole_2005_emitter() -> None:
    # D.7 PRODUCES 2005; it CONSUMES the 2002/2003/2004/6003 producers above.
    assert OCSF_CLASS_UID == 2005
    assert "investigation" not in SOURCE_AGENTS  # D.7 does not consume itself


def test_aggregate_one_entry_per_source() -> None:
    evidence = FleetEvidence(tenant_id=_TENANT, by_agent=dict.fromkeys(SOURCE_AGENTS, ()))
    result = aggregate_fleet(evidence)
    assert {e.agent_id for e in result} == set(SOURCE_AGENTS)


def test_per_source_counts_not_aggregated() -> None:
    evidence = FleetEvidence(
        tenant_id=_TENANT,
        by_agent={
            **dict.fromkeys(SOURCE_AGENTS, ()),
            "compliance": (_rf("compliance", "C-1", class_uid=2003),),
            "audit": (_rf("audit", "A-1", class_uid=6003),),
        },
    )
    counts = {e.agent_id: e.finding_count for e in aggregate_fleet(evidence)}
    assert counts["compliance"] == 1
    assert counts["audit"] == 1
    assert counts["identity"] == 0


def test_per_source_class_uid_breakdown() -> None:
    e = enumerate_source(
        "runtime_threat",
        (_rf("runtime_threat", "R-1"), _rf("runtime_threat", "R-2", class_uid=2003)),
    )
    assert e.by_class_uid == {2004: 1, 2003: 1}


def test_all_evidence_ids_namespaced() -> None:
    evidence = FleetEvidence(
        tenant_id=_TENANT,
        by_agent={
            **dict.fromkeys(SOURCE_AGENTS, ()),
            "vulnerability": (_rf("vulnerability", "V-1"),),
        },
    )
    assert all_evidence_ids(evidence) == {"finding:V-1"}
