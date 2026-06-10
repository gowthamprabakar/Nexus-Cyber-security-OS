"""D.3 v0.2 Task 10 — MITRE technique emission into finding evidence tests."""

from __future__ import annotations

from runtime_threat.mitre.emission import (
    MITRE_EVIDENCE_KEY,
    attach_techniques,
    technique_evidence,
)
from runtime_threat.mitre.mapper import TechniqueMapping

_MAPS = [
    TechniqueMapping("T1071", 0.9, "Application Layer Protocol"),
    TechniqueMapping("T1059", 0.8, "Command and Scripting Interpreter"),
]


def test_technique_evidence_format() -> None:
    assert technique_evidence(_MAPS) == [
        {"technique_id": "T1071", "confidence": 0.9, "name": "Application Layer Protocol"},
        {"technique_id": "T1059", "confidence": 0.8, "name": "Command and Scripting Interpreter"},
    ]


def test_attach_adds_technique_block() -> None:
    out = attach_techniques({"process": "bash"}, _MAPS)
    assert out["process"] == "bash"
    assert [t["technique_id"] for t in out[MITRE_EVIDENCE_KEY]] == ["T1071", "T1059"]


def test_attach_empty_is_byte_identical() -> None:
    # WI-R5: no mappings → evidence unchanged (no key added).
    ev = {"process": "bash", "container": "c1"}
    assert attach_techniques(ev, []) == ev
    assert MITRE_EVIDENCE_KEY not in attach_techniques(ev, [])


def test_attach_does_not_mutate_input() -> None:
    ev = {"process": "bash"}
    attach_techniques(ev, _MAPS)
    assert MITRE_EVIDENCE_KEY not in ev  # original untouched


def test_confidence_passed_through_verbatim() -> None:
    out = attach_techniques({}, [TechniqueMapping("T1611", 0.6, "Escape to Host")])
    assert out[MITRE_EVIDENCE_KEY][0]["confidence"] == 0.6


def test_empty_mappings_empty_evidence_list() -> None:
    assert technique_evidence([]) == []
