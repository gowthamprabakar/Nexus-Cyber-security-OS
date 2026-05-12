"""Tests for `investigation.tools.related_findings` (D.7 Task 5).

Cross-agent workspace reader. D.7's first tool that reads from
**sibling-agent artifacts** instead of a substrate store — the operator
pins `sibling_workspaces` in the contract (Q3 of the D.7 plan), and
D.7 reads each sibling's `findings.json` to chain into the
investigation.

Production contract:

- `find_related_findings(sibling_workspaces)` is async per ADR-005
  (filesystem reads run in `asyncio.to_thread` for parallel fan-out).
- Returns `tuple[RelatedFinding, ...]` — each item carries the
  sibling's `agent`, `run_id`, `class_uid`, and the raw OCSF payload.
- Forgiving: missing `findings.json` → skipped (matches the JSONL
  reader's posture from F.6 Task 6); malformed JSON → skipped with
  a logger warning. A single bad sibling doesn't poison the others.
- Per-workspace caller responsibility: the contract's `permitted_tools`
  must include `find_related_findings`, and the operator must pass
  only paths the agent is authorized to read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from investigation.tools.related_findings import RelatedFinding, find_related_findings

_TENANT_A = "01HV0T0000000000000000TENA"


def _write_findings_json(
    workspace: Path,
    *,
    agent: str,
    run_id: str,
    findings: list[dict[str, object]],
) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": agent,
        "agent_version": "0.1.0",
        "customer_id": _TENANT_A,
        "run_id": run_id,
        "findings": findings,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


def _ocsf_finding(*, class_uid: int, finding_uid: str) -> dict[str, object]:
    return {
        "class_uid": class_uid,
        "class_name": "Detection Finding",
        "finding_info": {"uid": finding_uid},
        "severity_id": 3,
    }


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_reads_findings_from_single_sibling(tmp_path: Path) -> None:
    ws = tmp_path / "runtime_threat" / "run-001"
    _write_findings_json(
        ws,
        agent="runtime_threat",
        run_id="run-001",
        findings=[
            _ocsf_finding(class_uid=2004, finding_uid="F-1"),
            _ocsf_finding(class_uid=2004, finding_uid="F-2"),
        ],
    )

    out = await find_related_findings(sibling_workspaces=(ws,))
    assert len(out) == 2
    assert all(isinstance(r, RelatedFinding) for r in out)
    assert out[0].source_agent == "runtime_threat"
    assert out[0].source_run_id == "run-001"
    assert out[0].class_uid == 2004
    assert {r.payload["finding_info"]["uid"] for r in out} == {"F-1", "F-2"}


@pytest.mark.asyncio
async def test_reads_from_multiple_siblings(tmp_path: Path) -> None:
    ws_rt = tmp_path / "runtime_threat" / "run-001"
    _write_findings_json(
        ws_rt,
        agent="runtime_threat",
        run_id="run-001",
        findings=[_ocsf_finding(class_uid=2004, finding_uid="RT-1")],
    )
    ws_cp = tmp_path / "cloud_posture" / "run-002"
    _write_findings_json(
        ws_cp,
        agent="cloud_posture",
        run_id="run-002",
        findings=[
            _ocsf_finding(class_uid=2003, finding_uid="CP-1"),
            _ocsf_finding(class_uid=2003, finding_uid="CP-2"),
        ],
    )

    out = await find_related_findings(sibling_workspaces=(ws_rt, ws_cp))
    assert len(out) == 3
    agents = {r.source_agent for r in out}
    assert agents == {"runtime_threat", "cloud_posture"}


@pytest.mark.asyncio
async def test_preserves_class_uid_diversity(tmp_path: Path) -> None:
    """D.7 routes on class_uid downstream; the reader must carry it through
    intact (e.g., 2003 Compliance, 2004 Detection, 2005 Incident).
    """
    ws_a = tmp_path / "cloud_posture" / "r1"
    _write_findings_json(
        ws_a,
        agent="cloud_posture",
        run_id="r1",
        findings=[_ocsf_finding(class_uid=2003, finding_uid="CP-1")],
    )
    ws_b = tmp_path / "identity" / "r2"
    _write_findings_json(
        ws_b,
        agent="identity",
        run_id="r2",
        findings=[_ocsf_finding(class_uid=2004, finding_uid="ID-1")],
    )
    out = await find_related_findings(sibling_workspaces=(ws_a, ws_b))
    class_uids = {r.class_uid for r in out}
    assert class_uids == {2003, 2004}


# ---------------------------- forgiveness ------------------------------


@pytest.mark.asyncio
async def test_missing_findings_json_is_skipped(tmp_path: Path) -> None:
    """A sibling workspace that exists but has no findings.json is
    skipped silently. Don't poison the others.
    """
    ws_a = tmp_path / "runtime_threat" / "r1"
    ws_a.mkdir(parents=True)  # exists, but no findings.json
    ws_b = tmp_path / "cloud_posture" / "r2"
    _write_findings_json(
        ws_b,
        agent="cloud_posture",
        run_id="r2",
        findings=[_ocsf_finding(class_uid=2003, finding_uid="CP-1")],
    )

    out = await find_related_findings(sibling_workspaces=(ws_a, ws_b))
    assert len(out) == 1
    assert out[0].source_agent == "cloud_posture"


@pytest.mark.asyncio
async def test_malformed_findings_json_is_skipped(tmp_path: Path) -> None:
    ws_a = tmp_path / "runtime_threat" / "r1"
    ws_a.mkdir(parents=True)
    (ws_a / "findings.json").write_text("this is not json {{{", encoding="utf-8")
    ws_b = tmp_path / "cloud_posture" / "r2"
    _write_findings_json(
        ws_b,
        agent="cloud_posture",
        run_id="r2",
        findings=[_ocsf_finding(class_uid=2003, finding_uid="CP-1")],
    )

    out = await find_related_findings(sibling_workspaces=(ws_a, ws_b))
    assert len(out) == 1
    assert out[0].source_agent == "cloud_posture"


@pytest.mark.asyncio
async def test_non_existent_workspace_path_is_skipped(tmp_path: Path) -> None:
    ws = tmp_path / "no-such-agent" / "no-such-run"
    out = await find_related_findings(sibling_workspaces=(ws,))
    assert out == ()


@pytest.mark.asyncio
async def test_empty_sibling_tuple_returns_empty(tmp_path: Path) -> None:
    out = await find_related_findings(sibling_workspaces=())
    assert out == ()


@pytest.mark.asyncio
async def test_findings_json_with_no_findings_array_is_skipped(tmp_path: Path) -> None:
    """The wrapper exists but `findings: []` — that's an empty sibling
    report. Return zero RelatedFindings for that workspace; don't raise.
    """
    ws = tmp_path / "runtime_threat" / "r1"
    _write_findings_json(
        ws,
        agent="runtime_threat",
        run_id="r1",
        findings=[],
    )
    out = await find_related_findings(sibling_workspaces=(ws,))
    assert out == ()
