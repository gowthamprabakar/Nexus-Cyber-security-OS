"""compliance v0.2 Task 3 — CIS-Azure reader + real-rule wiring guard (WI-C2)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import yaml
from compliance.tools.cis_azure_benchmark import (
    default_cis_azure_v2_path,
    read_cis_azure_benchmark,
)

# D.5 multi-cloud-posture's stable CIS-Azure rule ids (ground-truthed from
# multi_cloud_posture/rules_azure/cis_rules.py, 2026-06-11).
_REAL_AZURE_RULES = {
    "MCSPM-AZURE-STORAGE-001",
    "MCSPM-AZURE-STORAGE-002",
    "MCSPM-AZURE-KEYVAULT-001",
    "MCSPM-AZURE-KEYVAULT-002",
    "MCSPM-AZURE-NSG-001",
    "MCSPM-AZURE-NSG-002",
    "MCSPM-AZURE-SQL-001",
    "MCSPM-AZURE-APPSERVICE-001",
}

_LIB = default_cis_azure_v2_path()


def _controls() -> list[dict]:
    data = yaml.safe_load(Path(_LIB).read_text(encoding="utf-8"))
    return [c for c in data["controls"] if isinstance(c, dict)]


def _mappings(control: dict) -> list[dict]:
    return [m for m in (control.get("source_mappings") or []) if isinstance(m, dict)]


def test_default_path_exists() -> None:
    assert Path(_LIB).is_file() and _LIB.name == "cis_azure_v2.yaml"


def test_reader_loads_controls() -> None:
    controls = asyncio.run(read_cis_azure_benchmark())
    assert len(controls) >= 14
    assert any(c.control_id == "3.1" for c in controls)


def test_every_mapping_is_a_real_d5_rule() -> None:
    """No fabricated coverage: every mapping references a rule D.5 actually emits."""
    for control in _controls():
        for m in _mappings(control):
            assert m.get("source_agent") == "multi_cloud_posture"
            assert m["source_rule_id"] in _REAL_AZURE_RULES, (
                f"control {control['control_id']} maps to non-emitted rule {m['source_rule_id']!r}"
            )


def test_expected_controls_wired() -> None:
    by_id = {c["control_id"]: {m["source_rule_id"] for m in _mappings(c)} for c in _controls()}
    assert by_id["3.1"] == {"MCSPM-AZURE-STORAGE-002"}
    assert by_id["6.1"] == {"MCSPM-AZURE-NSG-002"}  # RDP
    assert by_id["6.2"] == {"MCSPM-AZURE-NSG-001"}  # SSH
    assert by_id["9.2"] == {"MCSPM-AZURE-APPSERVICE-001"}


def test_wired_count_is_eight() -> None:
    wired = [c for c in _controls() if _mappings(c)]
    assert len(wired) == 8  # all 8 D.5 Azure rules covered
