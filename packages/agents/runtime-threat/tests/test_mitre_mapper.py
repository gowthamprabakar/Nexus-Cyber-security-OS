"""D.3 v0.2 Task 9 — event → MITRE technique mapping tests."""

from __future__ import annotations

from datetime import UTC, datetime

from runtime_threat.mitre.catalog import MitreCatalog
from runtime_threat.mitre.mapper import (
    MappingRule,
    TechniqueMapping,
    falco_signals,
    map_signals,
    tracee_signals,
)
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.tracee import TraceeAlert

_RX = datetime(2026, 6, 10, tzinfo=UTC)


def test_maps_rule_name_to_technique() -> None:
    [m] = map_signals({"Terminal shell in container"})
    assert m == TechniqueMapping("T1059", 0.8, "")


def test_maps_via_tag() -> None:
    [m] = map_signals({"mitre_command_and_control"})
    assert m.technique_id == "T1071" and m.confidence == 0.9


def test_no_match_returns_empty() -> None:
    assert map_signals({"unrelated"}) == []


def test_multiple_matches_sorted_by_confidence() -> None:
    out = map_signals({"Terminal shell in container", "Outbound connection to C2"})
    assert [m.technique_id for m in out] == ["T1071", "T1059"]  # 0.9 before 0.8


def test_dedup_same_technique_highest_confidence() -> None:
    rules = (
        MappingRule(frozenset({"x"}), "T1", 0.5),
        MappingRule(frozenset({"y"}), "T1", 0.9),
    )
    [m] = map_signals({"x", "y"}, rules)
    assert m.technique_id == "T1" and m.confidence == 0.9


def test_catalog_enriches_name() -> None:
    cat = MitreCatalog()
    cat.load(
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            }
        ]
    )
    [m] = map_signals({"shell"}, catalog=cat)
    assert m.technique_id == "T1059" and m.name == "Command and Scripting Interpreter"


def test_falco_signals() -> None:
    alert = FalcoAlert(
        time=_RX,
        rule="Terminal shell in container",
        priority="Warning",
        output="",
        tags=("shell", "mitre_execution"),
    )
    assert falco_signals(alert) == {"Terminal shell in container", "shell", "mitre_execution"}
    assert map_signals(falco_signals(alert))[0].technique_id == "T1059"


def test_tracee_signals() -> None:
    alert = TraceeAlert(
        timestamp=_RX,
        event_name="security_file_open",
        process_name="cat",
        process_id=1,
        host_name="h",
        container_image="i",
        container_id="c",
    )
    assert tracee_signals(alert) == {"security_file_open"}
    assert map_signals(tracee_signals(alert))[0].technique_id == "T1005"
