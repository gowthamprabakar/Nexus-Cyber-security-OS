"""D.8 v0.2 Task 14 — basic threat-actor matching tests."""

from __future__ import annotations

from threat_intel.correlators.threat_actor import (
    ThreatActor,
    build_threat_actor_index,
    match_threat_actors,
)


def _ap(ap_id: str, tcode: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": ap_id,
        "external_references": [{"source_name": "mitre-attack", "external_id": tcode}],
    }


def _uses(src: str, tgt: str) -> dict:
    return {
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": src,
        "target_ref": tgt,
    }


_STIX = [
    {
        "type": "intrusion-set",
        "id": "intrusion-set--apt1",
        "name": "APT1",
        "aliases": ["Comment Crew"],
    },
    {"type": "intrusion-set", "id": "intrusion-set--apt2", "name": "APT2", "aliases": []},
    _ap("attack-pattern--a", "T1059"),
    _ap("attack-pattern--b", "T1566"),
    _ap("attack-pattern--c", "T1486"),
    _uses("intrusion-set--apt1", "attack-pattern--a"),
    _uses("intrusion-set--apt1", "attack-pattern--b"),
    _uses("intrusion-set--apt2", "attack-pattern--c"),
]


def test_build_index_maps_actor_to_techniques() -> None:
    idx = build_threat_actor_index(_STIX)
    assert idx["intrusion-set--apt1"].techniques == frozenset({"T1059", "T1566"})
    assert idx["intrusion-set--apt1"].aliases == ("Comment Crew",)
    assert idx["intrusion-set--apt2"].techniques == frozenset({"T1486"})


def test_actor_without_uses_has_empty_techniques() -> None:
    idx = build_threat_actor_index(
        [{"type": "intrusion-set", "id": "intrusion-set--x", "name": "X"}]
    )
    assert idx["intrusion-set--x"].techniques == frozenset()


def test_match_returns_actor_with_confidence() -> None:
    idx = build_threat_actor_index(_STIX)
    matches = match_threat_actors(["T1059", "T1566"], idx)
    assert matches[0].name == "APT1"
    assert matches[0].confidence == 1.0  # both of APT1's 2 techniques observed
    assert matches[0].matched_techniques == ("T1059", "T1566")


def test_partial_match_confidence() -> None:
    idx = build_threat_actor_index(_STIX)
    matches = match_threat_actors(["T1059"], idx)
    assert len(matches) == 1
    assert matches[0].name == "APT1" and matches[0].confidence == 0.5  # 1 of 2


def test_multiple_actors_sorted_by_confidence() -> None:
    idx = build_threat_actor_index(_STIX)
    # T1486 fully covers APT2 (1/1=1.0); T1059 covers half of APT1 (0.5).
    matches = match_threat_actors(["T1059", "T1486"], idx)
    assert [m.name for m in matches] == ["APT2", "APT1"]
    assert matches[0].confidence == 1.0 and matches[1].confidence == 0.5


def test_no_match_returns_empty() -> None:
    idx = build_threat_actor_index(_STIX)
    assert match_threat_actors(["T9999"], idx) == []


def test_min_confidence_filter() -> None:
    idx = build_threat_actor_index(_STIX)
    matches = match_threat_actors(["T1059", "T1486"], idx, min_confidence=0.9)
    assert [m.name for m in matches] == ["APT2"]  # APT1's 0.5 filtered out


def test_empty_index_no_matches() -> None:
    assert match_threat_actors(["T1059"], {}) == []


def test_actor_with_no_techniques_never_matches() -> None:
    idx = {"intrusion-set--x": ThreatActor("intrusion-set--x", "X", (), frozenset())}
    assert match_threat_actors(["T1059"], idx) == []
