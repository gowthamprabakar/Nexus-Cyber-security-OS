"""Shared per-source mapping index used by both Task 6 + Task 7 correlators.

The bundled CIS control library (Task 4) carries ``source_mappings``
per control — a list of ``ControlMapping`` records keyed by
``(source_agent, source_rule_id)``. Each correlator (Tasks 6 + 7)
needs to look up "given this source-agent rule_id, which CIS
controls map to it?" in O(1) per source finding.

This module flattens the library into a forward index keyed by
``(source_agent, source_rule_id)`` so each correlator can avoid a
linear scan over the full library.

The index is **rebuilt per agent run** during Stage 2 ENRICH — it's
read-only after construction and shared by reference to both
correlator TaskGroup branches.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from compliance.schemas import ComplianceFramework, ControlMapping
from compliance.tools.cis_aws_benchmark import CisControl

# (source_agent, source_rule_id) -> list of CIS controls + their per-
# mapping (level, required) overrides. Mapping so the correlators can
# accept both built dicts and read-only views.
type ControlIndexKey = tuple[str, str]
type ControlIndex = Mapping[ControlIndexKey, tuple["IndexedMapping", ...]]


@dataclass(frozen=True, slots=True)
class IndexedMapping:
    """A pre-folded record bundling a CIS control with one of its
    per-source mappings.

    The correlator only needs the control_id + level + required + name
    to emit a ComplianceFinding; carrying the full ``CisControl`` here
    is convenient but heavier than needed for the hot path.
    """

    framework: ComplianceFramework
    control_id: str
    control_name: str
    control_description: str
    mapping: ControlMapping


def build_control_index(
    controls: Iterable[CisControl],
    *,
    framework: ComplianceFramework = ComplianceFramework.CIS_AWS_V3,
) -> dict[ControlIndexKey, tuple[IndexedMapping, ...]]:
    """Flatten the CIS control library into a forward index.

    For each control's ``source_mappings`` entry, an ``IndexedMapping``
    record is appended to the bucket at
    ``(mapping.source_agent, mapping.source_rule_id)``. The resulting
    index lets each correlator look up "given this F.3 / D.5 rule_id,
    which CIS controls fail?" in O(1).
    """
    out: dict[ControlIndexKey, list[IndexedMapping]] = {}
    for control in controls:
        for mapping in control.source_mappings:
            key: ControlIndexKey = (mapping.source_agent, mapping.source_rule_id)
            out.setdefault(key, []).append(
                IndexedMapping(
                    framework=framework,
                    control_id=control.control_id,
                    control_name=control.name,
                    control_description=control.description,
                    mapping=mapping,
                )
            )
    return {k: tuple(v) for k, v in out.items()}


def build_control_by_id(controls: Iterable[CisControl]) -> dict[str, CisControl]:
    """Index controls by ``control_id`` for native-CIS attribution (A-3).

    The native-CIS correlation path (cloud-posture findings carrying Prowler's own
    ``evidence.cis_controls``) needs to resolve a bare ``control_id`` → its
    ``CisControl`` (name/description/level/required), independent of the
    ``source_mappings`` forward index. Last definition wins on duplicate ids.
    """
    return {control.control_id: control for control in controls}


__all__ = [
    "ControlIndex",
    "ControlIndexKey",
    "IndexedMapping",
    "build_control_by_id",
    "build_control_index",
]
