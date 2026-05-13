"""Tests for `multi_cloud_posture.tools.gcp_scc`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from multi_cloud_posture.tools.gcp_scc import GcpSccReaderError, read_gcp_findings


def _finding(
    *,
    name: str = "organizations/123/sources/456/findings/finding-001",
    category: str = "PUBLIC_BUCKET",
    severity: str = "HIGH",
    resource_name: str = "//storage.googleapis.com/projects/my-project/buckets/public-bucket",
    state: str = "ACTIVE",
    event_time: str = "2026-05-13T12:00:00Z",
    description: str = "Bucket allows public access via allUsers.",
) -> dict[str, Any]:
    return {
        "name": name,
        "parent": name.split("/findings/")[0],
        "resourceName": resource_name,
        "category": category,
        "state": state,
        "severity": severity,
        "description": description,
        "eventTime": event_time,
        "createTime": event_time,
        "sourceProperties": {"ReactivationCount": 0},
        "compliances": [{"standard": "cis", "version": "1.2.0"}],
        "mitreAttack": {"primaryTactic": "INITIAL_ACCESS"},
    }


def _write_canonical(tmp_path: Path, findings: list[dict[str, Any]]) -> Path:
    """SCC's canonical ListFindingsResponse: `{"listFindingsResults": [{"finding": ..., "resource": ...}]}`."""
    p = tmp_path / "scc.json"
    results = [
        {
            "finding": f,
            "resource": {
                "name": f.get("resourceName", ""),
                "projectName": "projects/my-project",
            },
        }
        for f in findings
    ]
    p.write_text(json.dumps({"listFindingsResults": results}))
    return p


def _write_gcloud(tmp_path: Path, findings: list[dict[str, Any]]) -> Path:
    """`gcloud scc findings list --format=json` shape: `{"findings": [...]}`."""
    p = tmp_path / "scc.json"
    p.write_text(json.dumps({"findings": findings}))
    return p


def _write_bare(tmp_path: Path, findings: list[dict[str, Any]]) -> Path:
    """Bare findings array."""
    p = tmp_path / "scc.json"
    p.write_text(json.dumps(findings))
    return p


# ---------------------------- canonical shape ----------------------------


@pytest.mark.asyncio
async def test_canonical_listfindings_response(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [_finding()])

    out = await read_gcp_findings(path=path)
    assert len(out) == 1
    f = out[0]
    assert f.finding_name == "organizations/123/sources/456/findings/finding-001"
    assert f.parent == "organizations/123/sources/456"
    assert f.category == "PUBLIC_BUCKET"
    assert f.severity == "HIGH"
    assert f.state == "ACTIVE"
    assert f.project_id == "my-project"
    assert f.resource_name.endswith("/public-bucket")
    assert f.detected_at == datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    assert f.unmapped["compliances"][0]["standard"] == "cis"
    assert f.unmapped["mitreAttack"]["primaryTactic"] == "INITIAL_ACCESS"
    assert f.unmapped["resource"]["projectName"] == "projects/my-project"


# ---------------------------- alternate shapes ---------------------------


@pytest.mark.asyncio
async def test_gcloud_findings_wrapper(tmp_path: Path) -> None:
    path = _write_gcloud(tmp_path, [_finding()])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_bare_findings_array(tmp_path: Path) -> None:
    path = _write_bare(tmp_path, [_finding()])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1


# ---------------------------- severity / state ---------------------------


@pytest.mark.parametrize(
    "severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"],
)
@pytest.mark.asyncio
async def test_all_severities_accepted(tmp_path: Path, severity: str) -> None:
    path = _write_canonical(tmp_path, [_finding(severity=severity)])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == severity


@pytest.mark.asyncio
async def test_lowercase_severity_normalised(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [_finding(severity="high")])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_unknown_severity_dropped(tmp_path: Path) -> None:
    path = _write_canonical(tmp_path, [_finding(severity="CATASTROPHIC")])
    out = await read_gcp_findings(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_inactive_state_still_parsed(tmp_path: Path) -> None:
    """SCC `state: INACTIVE` records still ride through — operators may want to see closed findings."""
    path = _write_canonical(tmp_path, [_finding(state="INACTIVE")])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1
    assert out[0].state == "INACTIVE"


# ---------------------------- forgiving on bad data ----------------------


@pytest.mark.asyncio
async def test_missing_name_dropped(tmp_path: Path) -> None:
    bad = _finding()
    bad["name"] = ""
    path = _write_canonical(tmp_path, [bad, _finding()])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_missing_resource_name_dropped(tmp_path: Path) -> None:
    bad = _finding()
    bad["resourceName"] = ""
    path = _write_canonical(tmp_path, [bad, _finding()])
    # The canonical writer also fills `resource.name`; we have to wipe both.
    raw_blob = json.loads(path.read_text())
    raw_blob["listFindingsResults"][0]["resource"]["name"] = ""
    path.write_text(json.dumps(raw_blob))

    out = await read_gcp_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_missing_category_dropped(tmp_path: Path) -> None:
    bad = _finding()
    bad["category"] = ""
    path = _write_canonical(tmp_path, [bad, _finding()])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_parent_derived_when_missing(tmp_path: Path) -> None:
    """If `parent` is absent, derive it from the `name` path."""
    f = _finding()
    del f["parent"]
    path = _write_canonical(tmp_path, [f])
    out = await read_gcp_findings(path=path)
    assert len(out) == 1
    assert out[0].parent == "organizations/123/sources/456"


@pytest.mark.asyncio
async def test_resource_name_falls_back_to_resource_blob(tmp_path: Path) -> None:
    """When finding.resourceName is absent, use the `resource.name` from the wrapper."""
    f = _finding()
    del f["resourceName"]
    # Build the canonical wrapper directly with a non-empty resource.name to
    # exercise the fallback path the parser provides.
    p = tmp_path / "scc.json"
    p.write_text(
        json.dumps(
            {
                "listFindingsResults": [
                    {
                        "finding": f,
                        "resource": {
                            "name": "//storage.googleapis.com/projects/my-project/buckets/public-bucket",
                            "projectName": "projects/my-project",
                        },
                    }
                ]
            }
        )
    )

    out = await read_gcp_findings(path=p)
    assert len(out) == 1
    assert out[0].resource_name.endswith("/public-bucket")


# ---------------------------- project_id extraction ----------------------


@pytest.mark.asyncio
async def test_project_id_from_compute_resource(tmp_path: Path) -> None:
    rid = "//compute.googleapis.com/projects/proj-xyz/zones/us-central1-a/instances/instance-1"
    path = _write_canonical(tmp_path, [_finding(resource_name=rid)])
    out = await read_gcp_findings(path=path)
    assert out[0].project_id == "proj-xyz"


@pytest.mark.asyncio
async def test_project_id_empty_when_no_projects_segment(tmp_path: Path) -> None:
    rid = "//cloudresourcemanager.googleapis.com/organizations/123"
    path = _write_canonical(tmp_path, [_finding(resource_name=rid)])
    out = await read_gcp_findings(path=path)
    assert out[0].project_id == ""


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(GcpSccReaderError, match="not found"):
        await read_gcp_findings(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(GcpSccReaderError, match="not a file"):
        await read_gcp_findings(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(GcpSccReaderError, match="malformed"):
        await read_gcp_findings(path=p)


@pytest.mark.asyncio
async def test_empty_results_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"listFindingsResults": []}))
    out = await read_gcp_findings(path=p)
    assert out == ()
