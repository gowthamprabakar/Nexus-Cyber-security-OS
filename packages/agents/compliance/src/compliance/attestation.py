"""PASS evidence collection per control (compliance v0.2 Task 7).

Decides whether a control can be **PASS-attested** and assembles its **positive evidence**
(WI-C6). The honest discipline: a control passes only when its mapped source rules were
**actually evaluated** (the source agent ran the check) AND none failed — NOT merely
"no FAIL was seen" (which could just mean the check never ran). The attestation records
which rules were checked + any passing source finding ids, so a PASS carries proof, not an
absence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ControlAttestation:
    control_id: str
    framework: str
    checked_rules: tuple[str, ...]  # the control's mapped rule ids that were evaluated
    source_finding_ids: tuple[str, ...] = field(default_factory=tuple)
    attested_at: str = ""

    def to_evidence(self) -> dict[str, object]:
        """The OCSF `evidences[0]` payload for `build_pass_finding` — positive evidence."""
        return {
            "kind": "compliance_pass",
            "control_id": self.control_id,
            "framework": self.framework,
            "checked_rules": list(self.checked_rules),
            "source_finding_ids": list(self.source_finding_ids),
            "attested_at": self.attested_at,
            "evidence_payload": {
                "evaluated_rule_count": len(self.checked_rules),
                "all_passing": True,
            },
        }


def control_can_be_attested(
    mapped_rule_ids: Iterable[str],
    *,
    evaluated_rule_ids: set[str],
    failing_rule_ids: set[str],
) -> bool:
    """A control may be PASS-attested iff it has ≥1 mapped rule, **all** its mapped rules
    were evaluated (positive evidence the checks ran), and **none** failed."""
    mapped = set(mapped_rule_ids)
    if not mapped:
        return False  # an unwired control has no evidence either way
    if not mapped <= evaluated_rule_ids:
        return False  # a mapped rule was never evaluated → unknown, not a PASS
    return mapped.isdisjoint(failing_rule_ids)


def build_attestation(
    *,
    control_id: str,
    framework: str,
    mapped_rule_ids: Iterable[str],
    source_finding_ids: Iterable[str] = (),
    attested_at: str,
) -> ControlAttestation:
    """Assemble the positive-evidence attestation for a passing control."""
    return ControlAttestation(
        control_id=control_id,
        framework=framework,
        checked_rules=tuple(sorted(set(mapped_rule_ids))),
        source_finding_ids=tuple(source_finding_ids),
        attested_at=attested_at,
    )
