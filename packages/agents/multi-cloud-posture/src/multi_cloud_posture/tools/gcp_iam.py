"""`read_gcp_iam_findings` — Cloud Asset Inventory IAM analyser.

Reads a GCP Cloud Asset Inventory IAM policies export and emits typed
`GcpIamFinding` records for overly-permissive bindings. Per ADR-005 the
filesystem read happens on `asyncio.to_thread`; the wrapper is `async`
for TaskGroup fan-out.

**Supported input shapes** (from `gcloud asset search-all-iam-policies
--format=json`):

1. **Bare array** — `[{...binding-record...}, ...]` where each record
   carries `name`, `assetType`, `project`, `policy.bindings[]`.
2. **`results` wrapper** — `{"results": [...]}` (the canonical Asset
   Inventory `SearchAllIamPoliciesResponse` shape).

**Flagging logic** (deterministic, no LLM):

- `roles/owner` granted to **any** non-Google-managed member → HIGH
- `roles/owner` granted to a `user:*@*` (especially with non-customer
  domain — heuristic: not on the bundled customer-domain allowlist
  passed by the caller) → CRITICAL
- `roles/editor` granted to a `user:*` → MEDIUM (broad write access)
- `serviceAccountUser` / `serviceAccountTokenCreator` on an `allUsers`
  or `allAuthenticatedUsers` member → CRITICAL (account-impersonation
  exposure)
- Public bindings (`allUsers` / `allAuthenticatedUsers`) on **any**
  predefined role → HIGH

**Stale service accounts** (per the plan): requires usage-events
timestamps from the IAM API which are NOT in Cloud Asset Inventory.
Deferred to Phase 1c when live SDK paths land.

Phase 1c live mode swaps the implementation behind this same signature
to `google-cloud-asset`'s `AssetServiceClient.search_all_iam_policies`
pager.

**Forgiving** on malformed entries (mirrors F.6 + Defender + SCC readers).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class GcpIamReaderError(RuntimeError):
    """The GCP IAM JSON feed could not be read."""


class GcpIamFinding(BaseModel):
    """One overly-permissive IAM binding flagged from Cloud Asset Inventory."""

    asset_name: str = Field(min_length=1)  # //service.googleapis.com/projects/<id>/...
    asset_type: str = Field(min_length=1)  # e.g. cloudresourcemanager.googleapis.com/Project
    project_id: str = ""
    role: str = Field(min_length=1)  # roles/owner / roles/editor / ...
    member: str = Field(min_length=1)  # user:alice@example.com / allUsers / ...
    severity: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW)$")
    reason: str = Field(min_length=1)  # human-readable explanation
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


# Roles that grant broad write/admin access — drive the HIGH/CRITICAL ladder.
_OWNER_ROLES: frozenset[str] = frozenset({"roles/owner", "roles/resourcemanager.organizationAdmin"})
_EDITOR_ROLES: frozenset[str] = frozenset({"roles/editor"})
_IMPERSONATION_ROLES: frozenset[str] = frozenset(
    {
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountTokenCreator",
    }
)
_PUBLIC_MEMBERS: frozenset[str] = frozenset({"allUsers", "allAuthenticatedUsers"})


async def read_gcp_iam_findings(
    *,
    path: Path,
    customer_domain_allowlist: tuple[str, ...] = (),
) -> tuple[GcpIamFinding, ...]:
    """Read a GCP Cloud Asset Inventory IAM JSON export and emit IAM findings.

    `customer_domain_allowlist` lists internal domains (`example.com`,
    `corp.example.com`) — `user:*@<allowlisted>` bindings to `roles/owner`
    are HIGH; bindings to external domains are CRITICAL.
    """
    return await asyncio.to_thread(_read_sync, path, customer_domain_allowlist)


def _read_sync(
    path: Path,
    customer_domain_allowlist: tuple[str, ...],
) -> tuple[GcpIamFinding, ...]:
    if not path.exists():
        raise GcpIamReaderError(f"gcp iam json not found: {path}")
    if not path.is_file():
        raise GcpIamReaderError(f"gcp iam json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise GcpIamReaderError(f"gcp iam json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    detected_at = datetime.now(UTC)
    allowlist = frozenset(d.lower() for d in customer_domain_allowlist)

    out: list[GcpIamFinding] = []
    for raw in raw_records:
        for finding in _flag_bindings(raw, detected_at=detected_at, allowlist=allowlist):
            out.append(finding)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    if isinstance(blob, list):
        return [r for r in blob if isinstance(r, dict)]
    if isinstance(blob, dict):
        results = blob.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return []
    return []


def _flag_bindings(
    record: dict[str, Any],
    *,
    detected_at: datetime,
    allowlist: frozenset[str],
) -> list[GcpIamFinding]:
    asset_name = str(record.get("name") or "")
    asset_type = str(record.get("assetType") or "")
    if not asset_name or not asset_type:
        return []
    project_id = _resolve_project_id(asset_name, record)
    policy = record.get("policy")
    if not isinstance(policy, dict):
        return []
    bindings = policy.get("bindings")
    if not isinstance(bindings, list):
        return []

    out: list[GcpIamFinding] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role") or "")
        members = binding.get("members")
        if not role or not isinstance(members, list):
            continue
        for raw_member in members:
            if not isinstance(raw_member, str) or not raw_member:
                continue
            finding = _classify_binding(
                asset_name=asset_name,
                asset_type=asset_type,
                project_id=project_id,
                role=role,
                member=raw_member,
                detected_at=detected_at,
                allowlist=allowlist,
                binding=binding,
            )
            if finding is not None:
                out.append(finding)
    return out


def _classify_binding(
    *,
    asset_name: str,
    asset_type: str,
    project_id: str,
    role: str,
    member: str,
    detected_at: datetime,
    allowlist: frozenset[str],
    binding: dict[str, Any],
) -> GcpIamFinding | None:
    """Apply the v0.1 flagging rules; return None if the binding is benign."""
    severity, reason = _grade_binding(role=role, member=member, allowlist=allowlist)
    if severity is None:
        return None
    unmapped: dict[str, Any] = {"binding": binding}
    try:
        return GcpIamFinding(
            asset_name=asset_name,
            asset_type=asset_type,
            project_id=project_id,
            role=role,
            member=member,
            severity=severity,
            reason=reason,
            detected_at=detected_at,
            unmapped=unmapped,
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _grade_binding(
    *,
    role: str,
    member: str,
    allowlist: frozenset[str],
) -> tuple[str, str] | tuple[None, str]:
    """Return (severity, reason) or (None, '') if the binding is benign."""
    # Public exposure (allUsers / allAuthenticatedUsers).
    if member in _PUBLIC_MEMBERS:
        if role in _IMPERSONATION_ROLES:
            return (
                "CRITICAL",
                f"Public principal {member!r} granted impersonation role {role!r} "
                f"— anyone on the internet can impersonate service accounts.",
            )
        return (
            "HIGH",
            f"Public principal {member!r} granted role {role!r} — "
            f"resource is exposed to anonymous principals.",
        )

    # Owner-role on a human user.
    if role in _OWNER_ROLES and member.startswith("user:"):
        domain = member.split("@", 1)[1].lower() if "@" in member else ""
        if allowlist and domain not in allowlist:
            return (
                "CRITICAL",
                f"User {member!r} (external domain {domain!r}) granted {role!r} "
                f"— grants full administrative control to a non-allowlisted user.",
            )
        return (
            "HIGH",
            f"User {member!r} granted {role!r} — broad administrative access; "
            f"prefer least-privilege predefined / custom roles.",
        )

    # Owner-role on a group / serviceAccount.
    if role in _OWNER_ROLES and member.startswith(("group:", "serviceAccount:")):
        return (
            "HIGH",
            f"{member!r} granted {role!r} — broad administrative access on this resource.",
        )

    # Editor-role on a human user.
    if role in _EDITOR_ROLES and member.startswith("user:"):
        return (
            "MEDIUM",
            f"User {member!r} granted {role!r} — broad write access; "
            f"prefer least-privilege predefined / custom roles.",
        )

    return (None, "")


def _resolve_project_id(asset_name: str, record: dict[str, Any]) -> str:
    """Prefer the explicit `project` field; fall back to parsing `name`."""
    project = record.get("project")
    if isinstance(project, str) and project:
        # `projects/<id>` form.
        return project.split("/")[-1]
    parts = asset_name.split("/projects/")
    if len(parts) >= 2:
        tail = parts[1]
        sep = tail.find("/")
        return tail if sep == -1 else tail[:sep]
    return ""


__all__ = [
    "GcpIamFinding",
    "GcpIamReaderError",
    "read_gcp_iam_findings",
]
