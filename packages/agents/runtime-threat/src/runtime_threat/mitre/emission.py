"""MITRE technique emission into finding evidence (D.3 v0.2 Task 10).

Formats `TechniqueMapping`s into a finding-evidence block and attaches them under the
`mitre_techniques` evidence key. **WI-R5 invariant:** attaching an *empty* mapping list
returns the evidence unchanged — so the offline/eval findings (which the deterministic
`run()` produces with no live mapping) stay **byte-identical**; only live-mapped
findings carry the technique block. Per Q3 the confidence is the mapper's static
heuristic value, passed through verbatim (not LLM-narrated).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from runtime_threat.mitre.mapper import TechniqueMapping

MITRE_EVIDENCE_KEY = "mitre_techniques"


def technique_evidence(mappings: Sequence[TechniqueMapping]) -> list[dict[str, Any]]:
    """Format technique mappings into evidence dicts (technique_id, confidence, name)."""
    return [
        {"technique_id": m.technique_id, "confidence": m.confidence, "name": m.name}
        for m in mappings
    ]


def attach_techniques(
    evidence: dict[str, Any], mappings: Sequence[TechniqueMapping]
) -> dict[str, Any]:
    """Return a NEW evidence dict with the mapped techniques attached under
    `MITRE_EVIDENCE_KEY`. With no mappings the evidence is returned unchanged (WI-R5
    byte-identical for offline findings). Never mutates the input."""
    out = dict(evidence)
    if mappings:
        out[MITRE_EVIDENCE_KEY] = technique_evidence(mappings)
    return out
