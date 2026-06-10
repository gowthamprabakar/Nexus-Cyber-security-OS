"""Basic threat-actor matching (D.8 v0.2 Task 14).

Per **Q6** v0.2 ships **basic** threat-actor detection: match observed ATT&CK techniques
to known actors. The actor → technique profiles are built from MITRE ATT&CK
``intrusion-set`` objects + their ``uses`` relationships to ``attack-pattern`` objects
(already ingested by the Task-7 MITRE feed). Confidence is a simple coverage heuristic.
Full attribution (campaign + multi-signal TTP analysis) is **v0.3**.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ThreatActor:
    actor_id: str
    name: str
    aliases: tuple[str, ...]
    techniques: frozenset[str]  # ATT&CK technique IDs (T-codes)


@dataclass(frozen=True, slots=True)
class ThreatActorMatch:
    actor_id: str
    name: str
    confidence: float
    matched_techniques: tuple[str, ...]


def _technique_id(attack_pattern: Mapping[str, Any]) -> str | None:
    for ref in attack_pattern.get("external_references", []):
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if ext:
                return str(ext)
    return None


def build_threat_actor_index(stix_objects: Sequence[Mapping[str, Any]]) -> dict[str, ThreatActor]:
    """Build ``actor_id → ThreatActor`` from MITRE STIX objects (intrusion-sets +
    attack-patterns + ``uses`` relationships)."""
    intrusion_sets: dict[str, tuple[str, tuple[str, ...]]] = {}
    ap_technique: dict[str, str] = {}
    uses: dict[str, set[str]] = defaultdict(set)

    for o in stix_objects:
        otype = o.get("type")
        if otype == "intrusion-set":
            intrusion_sets[str(o.get("id", ""))] = (
                str(o.get("name", "")),
                tuple(str(a) for a in o.get("aliases", [])),
            )
        elif otype == "attack-pattern":
            tcode = _technique_id(o)
            if tcode:
                ap_technique[str(o.get("id", ""))] = tcode
        elif otype == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = str(o.get("source_ref", "")), str(o.get("target_ref", ""))
            if src.startswith("intrusion-set--") and tgt.startswith("attack-pattern--"):
                uses[src].add(tgt)

    index: dict[str, ThreatActor] = {}
    for isid, (name, aliases) in intrusion_sets.items():
        techniques = frozenset(
            ap_technique[ap] for ap in uses.get(isid, set()) if ap in ap_technique
        )
        index[isid] = ThreatActor(actor_id=isid, name=name, aliases=aliases, techniques=techniques)
    return index


def match_threat_actors(
    observed_techniques: Iterable[str],
    index: Mapping[str, ThreatActor],
    *,
    min_confidence: float = 0.0,
) -> list[ThreatActorMatch]:
    """Match observed ATT&CK techniques to known actors.

    Confidence = fraction of the actor's known techniques that were observed (a basic
    coverage heuristic, Q6). Returns matches at/above ``min_confidence``, sorted by
    confidence then match count then name.
    """
    observed = frozenset(observed_techniques)
    matches: list[ThreatActorMatch] = []
    for actor in index.values():
        if not actor.techniques:
            continue
        matched = observed & actor.techniques
        if not matched:
            continue
        confidence = round(len(matched) / len(actor.techniques), 3)
        if confidence >= min_confidence:
            matches.append(
                ThreatActorMatch(
                    actor_id=actor.actor_id,
                    name=actor.name,
                    confidence=confidence,
                    matched_techniques=tuple(sorted(matched)),
                )
            )
    matches.sort(key=lambda m: (-m.confidence, -len(m.matched_techniques), m.name))
    return matches
