"""Extract Prowler's NATIVE CIS compliance attribution — A-3 (v0.3, Fork option B).

Prowler 5.x ``--output-formats json-ocsf`` carries each check's framework mappings
in the finding's ``unmapped.compliance`` object — a ``{framework: [control_ids]}``
dict, e.g.::

    "unmapped": {"compliance": {"CIS-3.0": ["1.10"], "MITRE-ATTACK": ["T1552"]}}

This module reads those native mappings rather than hardcoding a Prowler-check →
CIS table (which would risk drift / fabrication — the compliance cycle's hard
lesson). Only CIS frameworks are surfaced; everything else (MITRE, AWS-FSBP, …) is
ignored here. Absent/malformed ``unmapped.compliance`` yields ``()`` — so findings
from sources without native compliance metadata are unchanged.
"""

from __future__ import annotations

from typing import Any


def extract_cis_controls(raw: dict[str, Any]) -> tuple[str, ...]:
    """Return native CIS control attributions as ``"<framework>:<control_id>"``.

    Reads ``raw["unmapped"]["compliance"]`` (Prowler json-ocsf). Keeps only
    framework keys beginning with ``CIS`` (case-insensitive). Returns ``()`` when
    the field is absent or malformed — never raises on shape.
    """
    unmapped = raw.get("unmapped")
    if not isinstance(unmapped, dict):
        return ()
    compliance = unmapped.get("compliance")
    if not isinstance(compliance, dict):
        return ()
    controls: list[str] = []
    for framework, control_ids in compliance.items():
        if not isinstance(framework, str) or not framework.upper().startswith("CIS"):
            continue
        if not isinstance(control_ids, list):
            continue
        for control_id in control_ids:
            if isinstance(control_id, str) and control_id:
                controls.append(f"{framework}:{control_id}")
    return tuple(controls)


__all__ = ["extract_cis_controls"]
