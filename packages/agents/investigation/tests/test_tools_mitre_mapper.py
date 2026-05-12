"""Tests for `investigation.tools.mitre_mapper` (D.7 Task 7).

Bundled MITRE ATT&CK 14.x mapper. Heuristic keyword matching in v0.1;
ML / NER-based mapping deferred to Phase 1c.

Production contract:

- `map_to_mitre(evidence)` walks the input (str / dict / list / nested),
  matches keywords against the bundled ATT&CK table, and returns a
  ranked `tuple[MitreTechnique, ...]`.
- Ranking is by **number of keyword hits descending**, then by
  technique_id ascending (stable).
- Empty input → empty tuple. No matches → empty tuple. v0.1 doesn't
  fall back to a "T0000 Unknown" — operators see the absence as a
  signal that the evidence shape doesn't map to ATT&CK.
- The bundled table is a JSON file at `data/mitre_attack_14.json` —
  loadable at import time, immutable at runtime.
"""

from __future__ import annotations

from investigation.tools.mitre_mapper import map_to_mitre

# ---------------------------- single hit -------------------------------


def test_maps_shell_keyword_to_t1059() -> None:
    techniques = map_to_mitre("A shell spawned inside the container")
    ids = {t.technique_id for t in techniques}
    assert "T1059" in ids


def test_maps_s3_public_to_t1530() -> None:
    techniques = map_to_mitre("Public S3 bucket exposed")
    ids = {t.technique_id for t in techniques}
    assert "T1530" in ids


def test_maps_cve_keyword_to_t1190() -> None:
    techniques = map_to_mitre({"description": "Exploit of CVE-2024-12345 detected"})
    ids = {t.technique_id for t in techniques}
    assert "T1190" in ids


def test_maps_crypto_mining_to_t1496() -> None:
    techniques = map_to_mitre("xmrig crypto-mining process found")
    ids = {t.technique_id for t in techniques}
    assert "T1496" in ids


# ---------------------------- ranking ----------------------------------


def test_ranks_by_keyword_hit_count_descending() -> None:
    """Multi-keyword hit on one technique should rank above single-keyword."""
    evidence = "shell shell shell, also crypto-mining was mentioned once"
    techniques = map_to_mitre(evidence)
    # T1059 (shell) gets 3 hits; T1496 (crypto-mining) gets 1.
    assert techniques[0].technique_id == "T1059"


def test_stable_ordering_by_technique_id_on_tie() -> None:
    """When two techniques tie on hit count, technique_id ascending."""
    # Two phrases that hit T1059 and T1190 once each.
    evidence = "shell exploit"
    techniques = map_to_mitre(evidence)
    ids = [t.technique_id for t in techniques]
    # Both T1059 (1 hit) and T1190 (1 hit) appear; T1059 sorts before T1190.
    t1059_idx = ids.index("T1059")
    t1190_idx = ids.index("T1190")
    assert t1059_idx < t1190_idx


# ---------------------------- nested input ----------------------------


def test_walks_nested_dict_for_keywords() -> None:
    payload = {
        "finding": {
            "rule": "Terminal shell in container",
            "evidence": {"process": {"cmdline": "/bin/sh -i"}},
        }
    }
    techniques = map_to_mitre(payload)
    ids = {t.technique_id for t in techniques}
    assert "T1059" in ids


def test_walks_list_input() -> None:
    techniques = map_to_mitre(["unrelated string", "shell spawned", "another"])
    ids = {t.technique_id for t in techniques}
    assert "T1059" in ids


# ---------------------------- no matches -----------------------------


def test_empty_input_returns_empty_tuple() -> None:
    assert map_to_mitre("") == ()
    assert map_to_mitre({}) == ()
    assert map_to_mitre([]) == ()


def test_no_keyword_match_returns_empty_tuple() -> None:
    """No fallback to a 'T0000 Unknown' — operators see absence as signal."""
    techniques = map_to_mitre("benign log line about server uptime")
    assert techniques == ()


# ---------------------------- output shape ---------------------------


def test_returns_tuple_of_mitre_technique() -> None:
    from investigation.schemas import MitreTechnique

    techniques = map_to_mitre("shell spawn detected")
    assert isinstance(techniques, tuple)
    assert all(isinstance(t, MitreTechnique) for t in techniques)


def test_technique_has_tactic_attached() -> None:
    techniques = map_to_mitre("shell spawned")
    t1059 = next(t for t in techniques if t.technique_id == "T1059")
    assert t1059.tactic_id == "TA0002"
    assert t1059.tactic_name == "Execution"


def test_sub_technique_populated_when_table_has_it() -> None:
    """T1059 in the bundled table carries sub_technique T1059.004 (Unix Shell)."""
    techniques = map_to_mitre("shell spawned")
    t1059 = next(t for t in techniques if t.technique_id == "T1059")
    assert t1059.sub_technique_id == "T1059.004"
    assert t1059.sub_technique_name == "Unix Shell"


# ---------------------------- case insensitivity ---------------------


def test_keyword_matching_is_case_insensitive() -> None:
    """Operators paste evidence with mixed case; the matcher normalises."""
    techniques = map_to_mitre("SHELL SPAWN DETECTED")
    ids = {t.technique_id for t in techniques}
    assert "T1059" in ids
