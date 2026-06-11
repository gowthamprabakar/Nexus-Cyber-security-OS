"""compliance v0.2 Task 4 — CIS-GCP reader + real-rule wiring guard (WI-C2)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import yaml
from compliance.tools.cis_gcp_benchmark import (
    default_cis_gcp_v2_path,
    read_cis_gcp_benchmark,
)

# D.5 multi-cloud-posture's stable CIS-GCP rule ids (ground-truthed from
# multi_cloud_posture/rules_gcp/cis_rules.py, 2026-06-11).
_REAL_GCP_RULES = {
    "MCSPM-GCP-STORAGE-001",
    "MCSPM-GCP-STORAGE-002",
    "MCSPM-GCP-SQL-001",
    "MCSPM-GCP-SQL-002",
    "MCSPM-GCP-GCE-001",
    "MCSPM-GCP-GCE-002",
    "MCSPM-GCP-FIREWALL-001",
    "MCSPM-GCP-FIREWALL-002",
    "MCSPM-GCP-KMS-001",
    "MCSPM-GCP-BIGQUERY-001",
}

_LIB = default_cis_gcp_v2_path()


def _controls() -> list[dict]:
    data = yaml.safe_load(Path(_LIB).read_text(encoding="utf-8"))
    return [c for c in data["controls"] if isinstance(c, dict)]


def _mappings(control: dict) -> list[dict]:
    return [m for m in (control.get("source_mappings") or []) if isinstance(m, dict)]


def test_default_path_exists() -> None:
    assert Path(_LIB).is_file() and _LIB.name == "cis_gcp_v2.yaml"


def test_reader_loads_controls() -> None:
    controls = asyncio.run(read_cis_gcp_benchmark())
    assert len(controls) >= 13
    assert any(c.control_id == "5.1" for c in controls)


def test_every_mapping_is_a_real_d5_rule() -> None:
    """No fabricated coverage: every mapping references a rule D.5 actually emits."""
    for control in _controls():
        for m in _mappings(control):
            assert m.get("source_agent") == "multi_cloud_posture"
            assert m["source_rule_id"] in _REAL_GCP_RULES, (
                f"control {control['control_id']} maps to non-emitted rule {m['source_rule_id']!r}"
            )


def test_expected_controls_wired() -> None:
    by_id = {c["control_id"]: {m["source_rule_id"] for m in _mappings(c)} for c in _controls()}
    assert by_id["5.1"] == {"MCSPM-GCP-STORAGE-001"}
    assert by_id["3.6"] == {"MCSPM-GCP-FIREWALL-001"}  # SSH
    assert by_id["3.7"] == {"MCSPM-GCP-FIREWALL-002"}  # RDP
    assert by_id["7.1"] == {"MCSPM-GCP-BIGQUERY-001"}


def test_wired_count_is_ten() -> None:
    wired = [c for c in _controls() if _mappings(c)]
    assert len(wired) == 10  # all 10 D.5 GCP rules covered
