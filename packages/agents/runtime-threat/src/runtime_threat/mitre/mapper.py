"""Event → MITRE ATT&CK technique mapping engine (D.3 v0.2 Task 9).

A **basic rule-based** mapper (Q3): each rule matches a set of event *signals* (Falco
rule name + tags, or Tracee event name) and maps them to an ATT&CK technique id with a
**static heuristic confidence** (NOT LLM-narrated). The mapping is enriched with the
technique name from the Task-8 `MitreCatalog` when available. Full automated extraction
is v0.3.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from runtime_threat.mitre.catalog import MitreCatalog
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.tracee import TraceeAlert


@dataclass(frozen=True, slots=True)
class MappingRule:
    matches: frozenset[str]  # any signal in this set triggers the mapping
    technique_id: str
    confidence: float


@dataclass(frozen=True, slots=True)
class TechniqueMapping:
    technique_id: str
    confidence: float
    name: str = ""


#: The v0.2 starter mapping table — heuristic confidences, extended in v0.3.
DEFAULT_MAPPING_RULES: tuple[MappingRule, ...] = (
    MappingRule(
        frozenset({"Terminal shell in container", "shell", "mitre_execution"}), "T1059", 0.8
    ),
    MappingRule(
        frozenset({"Read sensitive file untrusted", "mitre_credential_access"}), "T1552", 0.7
    ),
    MappingRule(
        frozenset({"Outbound connection to C2", "mitre_command_and_control"}), "T1071", 0.9
    ),
    MappingRule(
        frozenset({"Launch privileged container", "mitre_privilege_escalation"}), "T1611", 0.6
    ),
    MappingRule(frozenset({"security_file_open"}), "T1005", 0.5),
    MappingRule(frozenset({"init_module", "kernel_module_loaded"}), "T1547", 0.7),
)


def falco_signals(alert: FalcoAlert) -> set[str]:
    """The signals a Falco alert contributes — its rule name + tags."""
    return {alert.rule, *alert.tags}


def tracee_signals(alert: TraceeAlert) -> set[str]:
    """The signals a Tracee alert contributes — its event name."""
    return {alert.event_name}


def map_signals(
    signals: Iterable[str],
    rules: Iterable[MappingRule] = DEFAULT_MAPPING_RULES,
    *,
    catalog: MitreCatalog | None = None,
) -> list[TechniqueMapping]:
    """Map a set of event signals to ATT&CK techniques. Each technique appears once
    (highest-confidence rule wins); results sort by confidence then id."""
    sigset = frozenset(signals)
    best: dict[str, float] = {}
    for rule in rules:
        if (sigset & rule.matches) and (
            rule.technique_id not in best or rule.confidence > best[rule.technique_id]
        ):
            best[rule.technique_id] = rule.confidence

    out: list[TechniqueMapping] = []
    for tid, conf in best.items():
        technique = catalog.get(tid) if catalog is not None else None
        out.append(TechniqueMapping(tid, conf, technique.name if technique else ""))
    out.sort(key=lambda m: (-m.confidence, m.technique_id))
    return out
