"""MITRE ATT&CK technique catalog (D.3 v0.2 Task 8).

Loads ATT&CK ``attack-pattern`` techniques from a STIX bundle into an in-memory catalog
(technique id → name + tactics) with refresh. D.8 Threat Intel produces the live STIX
feed; D.3 keeps a **self-contained** parser (no cross-agent dependency) so the runtime
mapper (Task 9) can resolve technique metadata locally. Per Q3 this backs a basic
rule-based mapping, not full automated extraction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...] = field(default_factory=tuple)


def _technique_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if ext:
                return str(ext)
    return ""


def _tactics(obj: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases", []):
        if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name")
            if name:
                out.append(str(name))
    return tuple(out)


def parse_techniques(stix_objects: Sequence[dict[str, Any]]) -> dict[str, MitreTechnique]:
    """Parse ``attack-pattern`` STIX objects → ``technique_id → MitreTechnique``."""
    catalog: dict[str, MitreTechnique] = {}
    for obj in stix_objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = _technique_id(obj)
        if not tid:
            continue
        catalog[tid] = MitreTechnique(
            technique_id=tid, name=str(obj.get("name", "")), tactics=_tactics(obj)
        )
    return catalog


class MitreCatalog:
    """An in-memory ATT&CK technique catalog with refresh."""

    def __init__(self) -> None:
        self._techniques: dict[str, MitreTechnique] = {}

    def load(self, stix_objects: Sequence[dict[str, Any]]) -> int:
        """Load techniques from STIX objects (merging into the catalog). Returns the
        number of techniques now known."""
        self._techniques.update(parse_techniques(stix_objects))
        return len(self._techniques)

    def refresh(self, stix_objects: Sequence[dict[str, Any]]) -> int:
        """Replace the catalog wholesale from a fresh STIX pull."""
        self._techniques = parse_techniques(stix_objects)
        return len(self._techniques)

    def get(self, technique_id: str) -> MitreTechnique | None:
        return self._techniques.get(technique_id)

    def all(self) -> tuple[MitreTechnique, ...]:
        return tuple(self._techniques.values())

    def __len__(self) -> int:
        return len(self._techniques)
