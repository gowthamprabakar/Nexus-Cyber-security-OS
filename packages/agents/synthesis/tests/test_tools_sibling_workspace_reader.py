"""Tests — ``synthesis.tools.sibling_workspace_reader`` (Task 3).

Validates the forgiving fan-out reader: error paths, parse path,
per-source isolation (a missing/malformed sibling never poisons the
others), the SiblingFindings dataclass shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from synthesis.tools.sibling_workspace_reader import (
    SiblingFindings,
    read_sibling_workspaces,
)


def _write_findings(workspace: Path, payloads: list[dict]) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "x",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "r",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": payloads,
            }
        ),
        encoding="utf-8",
    )
    return workspace


# ---------------------------------------------------------------------------
# SiblingFindings dataclass shape
# ---------------------------------------------------------------------------


def test_sibling_findings_defaults_to_empty_tuples() -> None:
    sf = SiblingFindings()
    assert sf.investigation == ()
    assert sf.compliance == ()
    assert sf.cloud_posture == ()
    assert sf.total_findings == 0
    assert sf.any_source_present is False


def test_sibling_findings_total_sums_per_source() -> None:
    sf = SiblingFindings(
        investigation=({"a": 1},),
        compliance=({"b": 2}, {"c": 3}),
        cloud_posture=(),
    )
    assert sf.total_findings == 3


def test_sibling_findings_is_frozen() -> None:
    sf = SiblingFindings()
    with pytest.raises(AttributeError):
        sf.investigation = ({"x": 1},)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# All-None / skip paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_none_workspaces_returns_all_empty() -> None:
    sf = await read_sibling_workspaces(
        investigation_workspace=None,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert sf.total_findings == 0


@pytest.mark.asyncio
async def test_missing_directory_path_returns_empty(tmp_path: Path) -> None:
    """Non-existent workspace path -> empty tuple for that source."""
    sf = await read_sibling_workspaces(
        investigation_workspace=tmp_path / "does_not_exist",
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert sf.investigation == ()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_source_round_trip(tmp_path: Path) -> None:
    ws = _write_findings(tmp_path / "d7", [{"finding_info": {"uid": "A"}, "class_uid": 2004}])
    sf = await read_sibling_workspaces(
        investigation_workspace=ws,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert len(sf.investigation) == 1
    assert sf.investigation[0]["finding_info"]["uid"] == "A"


@pytest.mark.asyncio
async def test_all_three_sources_round_trip(tmp_path: Path) -> None:
    inv = _write_findings(tmp_path / "d7", [{"finding_info": {"uid": "INV-1"}}])
    comp = _write_findings(
        tmp_path / "d6",
        [{"finding_info": {"uid": "COMP-1"}}, {"finding_info": {"uid": "COMP-2"}}],
    )
    cspm = _write_findings(tmp_path / "f3", [{"finding_info": {"uid": "CSPM-1"}}])
    sf = await read_sibling_workspaces(
        investigation_workspace=inv,
        compliance_workspace=comp,
        cloud_posture_workspace=cspm,
    )
    assert len(sf.investigation) == 1
    assert len(sf.compliance) == 2
    assert len(sf.cloud_posture) == 1
    assert sf.total_findings == 4


# ---------------------------------------------------------------------------
# Per-source isolation (a single bad sibling never poisons the others)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_findings_json_for_one_source_isolates(tmp_path: Path) -> None:
    """D.6 workspace exists but findings.json is malformed; D.7 valid;
    F.3 absent. D.7 contributes findings; D.6 contributes zero (with
    warning); F.3 contributes zero."""
    inv = _write_findings(tmp_path / "d7", [{"finding_info": {"uid": "INV-1"}}])
    bad_comp = tmp_path / "d6"
    bad_comp.mkdir(parents=True, exist_ok=True)
    (bad_comp / "findings.json").write_text("{nope-not-json", encoding="utf-8")

    sf = await read_sibling_workspaces(
        investigation_workspace=inv,
        compliance_workspace=bad_comp,
        cloud_posture_workspace=None,
    )
    assert len(sf.investigation) == 1
    assert sf.compliance == ()
    assert sf.cloud_posture == ()


@pytest.mark.asyncio
async def test_top_level_not_mapping_skipped(tmp_path: Path) -> None:
    """A JSON list at the top level (instead of mapping) is silently skipped."""
    weird = tmp_path / "weird"
    weird.mkdir(parents=True, exist_ok=True)
    (weird / "findings.json").write_text("[1, 2, 3]", encoding="utf-8")
    sf = await read_sibling_workspaces(
        investigation_workspace=weird,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert sf.investigation == ()


@pytest.mark.asyncio
async def test_findings_field_not_list_skipped(tmp_path: Path) -> None:
    """A `findings` field that isn't a list is silently skipped."""
    weird = tmp_path / "weird"
    weird.mkdir(parents=True, exist_ok=True)
    (weird / "findings.json").write_text(
        json.dumps({"agent": "x", "findings": "not_a_list"}), encoding="utf-8"
    )
    sf = await read_sibling_workspaces(
        investigation_workspace=weird,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert sf.investigation == ()


@pytest.mark.asyncio
async def test_non_dict_entries_in_findings_list_filtered(tmp_path: Path) -> None:
    """Garbage entries inside findings[] are silently dropped; sibling
    entries continue to parse."""
    ws = tmp_path / "mixed"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "x",
                "findings": [
                    {"finding_info": {"uid": "good-1"}},
                    "not_a_dict",
                    42,
                    {"finding_info": {"uid": "good-2"}},
                ],
            }
        ),
        encoding="utf-8",
    )
    sf = await read_sibling_workspaces(
        investigation_workspace=ws,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    uids = [f["finding_info"]["uid"] for f in sf.investigation]
    assert uids == ["good-1", "good-2"]


@pytest.mark.asyncio
async def test_empty_findings_list_returns_empty_tuple(tmp_path: Path) -> None:
    ws = _write_findings(tmp_path / "empty", [])
    sf = await read_sibling_workspaces(
        investigation_workspace=ws,
        compliance_workspace=None,
        cloud_posture_workspace=None,
    )
    assert sf.investigation == ()
