"""Tests for `multi_cloud_posture.tools.gcp_iam`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from multi_cloud_posture.tools.gcp_iam import GcpIamReaderError, read_gcp_iam_findings


def _binding(role: str, members: list[str]) -> dict[str, Any]:
    return {"role": role, "members": members}


def _record(
    *,
    asset_name: str = "//cloudresourcemanager.googleapis.com/projects/proj-xyz",
    asset_type: str = "cloudresourcemanager.googleapis.com/Project",
    project: str = "projects/proj-xyz",
    bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "name": asset_name,
        "assetType": asset_type,
        "project": project,
        "policy": {"bindings": bindings or []},
    }


def _write_bare(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    p = tmp_path / "iam.json"
    p.write_text(json.dumps(records))
    return p


def _write_results(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    p = tmp_path / "iam.json"
    p.write_text(json.dumps({"results": records}))
    return p


# ---------------------------- benign / pass-through ----------------------


@pytest.mark.asyncio
async def test_no_overly_permissive_emits_nothing(tmp_path: Path) -> None:
    """Predefined role on a service account is not flagged."""
    rec = _record(
        bindings=[
            _binding(
                "roles/iam.serviceAccountUser",
                ["serviceAccount:my-app@proj-xyz.iam.gserviceaccount.com"],
            ),
            _binding("roles/storage.objectViewer", ["user:alice@example.com"]),
        ]
    )
    path = _write_bare(tmp_path, [rec])
    out = await read_gcp_iam_findings(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_no_records_returns_empty(tmp_path: Path) -> None:
    path = _write_bare(tmp_path, [])
    out = await read_gcp_iam_findings(path=path)
    assert out == ()


# ---------------------------- public-member flagging ---------------------


@pytest.mark.asyncio
async def test_all_users_on_any_role_is_high(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/storage.objectViewer", ["allUsers"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    f = out[0]
    assert f.severity == "HIGH"
    assert f.member == "allUsers"
    assert f.role == "roles/storage.objectViewer"
    assert "anonymous" in f.reason.lower()


@pytest.mark.asyncio
async def test_all_authenticated_users_on_impersonation_role_is_critical(tmp_path: Path) -> None:
    rec = _record(
        bindings=[
            _binding("roles/iam.serviceAccountTokenCreator", ["allAuthenticatedUsers"]),
        ]
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    f = out[0]
    assert f.severity == "CRITICAL"
    assert "impersonate" in f.reason.lower()


# ---------------------------- owner-role flagging ------------------------


@pytest.mark.asyncio
async def test_owner_role_on_user_default_allowlist_is_high(tmp_path: Path) -> None:
    """No allowlist → owner-role on any user is HIGH (not CRITICAL)."""
    rec = _record(bindings=[_binding("roles/owner", ["user:alice@example.com"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_owner_role_on_user_external_domain_is_critical(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/owner", ["user:bob@external.com"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(
        path=path,
        customer_domain_allowlist=("example.com", "corp.example.com"),
    )
    assert len(out) == 1
    f = out[0]
    assert f.severity == "CRITICAL"
    assert "external" in f.reason.lower()


@pytest.mark.asyncio
async def test_owner_role_on_user_allowlisted_domain_is_high(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/owner", ["user:alice@example.com"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(
        path=path,
        customer_domain_allowlist=("example.com",),
    )
    assert len(out) == 1
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_owner_role_on_service_account_is_high(tmp_path: Path) -> None:
    rec = _record(
        bindings=[
            _binding(
                "roles/owner",
                ["serviceAccount:over-privileged@proj-xyz.iam.gserviceaccount.com"],
            ),
        ]
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_owner_role_on_group_is_high(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/owner", ["group:platform-admins@example.com"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == "HIGH"


# ---------------------------- editor-role flagging -----------------------


@pytest.mark.asyncio
async def test_editor_role_on_user_is_medium(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/editor", ["user:alice@example.com"])])
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].severity == "MEDIUM"


@pytest.mark.asyncio
async def test_editor_role_on_service_account_is_benign(tmp_path: Path) -> None:
    rec = _record(
        bindings=[_binding("roles/editor", ["serviceAccount:ci@proj-xyz.iam.gserviceaccount.com"])]
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    # SA gets the role for CI; not a finding in v0.1.
    assert out == ()


# ---------------------------- shape handling -----------------------------


@pytest.mark.asyncio
async def test_results_wrapper_shape(tmp_path: Path) -> None:
    rec = _record(bindings=[_binding("roles/owner", ["user:alice@example.com"])])
    path = _write_results(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_project_id_from_explicit_field(tmp_path: Path) -> None:
    rec = _record(
        asset_name="//compute.googleapis.com/projects/proj-xyz/zones/us-central1-a/instances/vm-1",
        project="projects/proj-explicit",
        bindings=[_binding("roles/owner", ["user:a@example.com"])],
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].project_id == "proj-explicit"


@pytest.mark.asyncio
async def test_project_id_from_asset_name_fallback(tmp_path: Path) -> None:
    rec = {
        "name": "//compute.googleapis.com/projects/proj-from-name/instances/vm-1",
        "assetType": "compute.googleapis.com/Instance",
        "policy": {"bindings": [_binding("roles/owner", ["user:a@example.com"])]},
    }
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].project_id == "proj-from-name"


# ---------------------------- malformed data -----------------------------


@pytest.mark.asyncio
async def test_missing_name_dropped(tmp_path: Path) -> None:
    bad = {"assetType": "x", "policy": {"bindings": []}}
    good = _record(bindings=[_binding("roles/owner", ["user:a@example.com"])])
    path = _write_bare(tmp_path, [bad, good])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].member == "user:a@example.com"


@pytest.mark.asyncio
async def test_missing_policy_dropped(tmp_path: Path) -> None:
    bad = {"name": "x", "assetType": "y"}
    path = _write_bare(tmp_path, [bad])
    out = await read_gcp_iam_findings(path=path)
    assert out == ()


@pytest.mark.asyncio
async def test_non_string_members_skipped(tmp_path: Path) -> None:
    rec = _record(
        bindings=[
            {
                "role": "roles/owner",
                "members": [None, 123, "user:alice@example.com"],
            }
        ]
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(path=path)
    assert len(out) == 1
    assert out[0].member == "user:alice@example.com"


# ---------------------------- multiple bindings per resource -------------


@pytest.mark.asyncio
async def test_multiple_bindings_yield_multiple_findings(tmp_path: Path) -> None:
    rec = _record(
        bindings=[
            _binding("roles/owner", ["user:alice@example.com", "user:bob@external.com"]),
            _binding("roles/editor", ["user:carol@example.com"]),
            _binding("roles/storage.admin", ["allUsers"]),
        ]
    )
    path = _write_bare(tmp_path, [rec])

    out = await read_gcp_iam_findings(
        path=path,
        customer_domain_allowlist=("example.com",),
    )
    # 2 owner bindings + 1 editor binding + 1 public binding = 4 findings
    severities = sorted(f.severity for f in out)
    assert severities == ["CRITICAL", "HIGH", "HIGH", "MEDIUM"]


# ---------------------------- file errors --------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(GcpIamReaderError, match="not found"):
        await read_gcp_iam_findings(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(GcpIamReaderError, match="not a file"):
        await read_gcp_iam_findings(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(GcpIamReaderError, match="malformed"):
        await read_gcp_iam_findings(path=p)
