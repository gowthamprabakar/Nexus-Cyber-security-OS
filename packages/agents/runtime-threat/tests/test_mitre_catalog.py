"""D.3 v0.2 Task 8 — MITRE ATT&CK technique catalog tests."""

from __future__ import annotations

from runtime_threat.mitre.catalog import MitreCatalog, MitreTechnique, parse_techniques


def _ap(tid: str, name: str, tactic: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
    }


_STIX = [
    _ap("T1059", "Command and Scripting Interpreter", "execution"),
    _ap("T1486", "Data Encrypted for Impact", "impact"),
    {"type": "malware", "id": "malware--x", "name": "ignored"},
]


def test_parse_techniques() -> None:
    cat = parse_techniques(_STIX)
    assert set(cat) == {"T1059", "T1486"}  # malware ignored
    assert cat["T1059"] == MitreTechnique(
        "T1059", "Command and Scripting Interpreter", ("execution",)
    )


def test_catalog_load_and_get() -> None:
    cat = MitreCatalog()
    assert cat.load(_STIX) == 2
    assert cat.get("T1059").name == "Command and Scripting Interpreter"
    assert cat.get("T9999") is None
    assert len(cat) == 2


def test_load_merges() -> None:
    cat = MitreCatalog()
    cat.load([_ap("T1059", "Shell", "execution")])
    cat.load([_ap("T1486", "Ransomware", "impact")])
    assert len(cat) == 2  # merged, not replaced


def test_refresh_replaces() -> None:
    cat = MitreCatalog()
    cat.load(_STIX)
    n = cat.refresh([_ap("T1003", "OS Credential Dumping", "credential-access")])
    assert n == 1 and len(cat) == 1
    assert cat.get("T1059") is None  # old catalog gone


def test_technique_without_external_id_skipped() -> None:
    cat = parse_techniques([{"type": "attack-pattern", "id": "attack-pattern--y", "name": "no-id"}])
    assert cat == {}


def test_all_returns_techniques() -> None:
    cat = MitreCatalog()
    cat.load(_STIX)
    assert {t.technique_id for t in cat.all()} == {"T1059", "T1486"}
