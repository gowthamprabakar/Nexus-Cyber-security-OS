"""`normalize_gcp` — GCP raw records → OCSF 2003 Compliance Findings.

Pure-function normalizer (no I/O, no async). Takes the typed reader
outputs from `tools/gcp_scc.py` and `tools/gcp_iam.py` and produces a
tuple of `CloudPostureFinding` (re-exported from F.3 via `schemas.py`).

**Severity mapping:**

| Source                  | Source value           | OCSF `Severity` |
| ----------------------- | ---------------------- | --------------- |
| SCC finding             | CRITICAL               | CRITICAL        |
| SCC finding             | HIGH                   | HIGH            |
| SCC finding             | MEDIUM                 | MEDIUM          |
| SCC finding             | LOW                    | LOW             |
| SCC finding             | SEVERITY_UNSPECIFIED   | INFO            |
| IAM finding (analyser)  | CRITICAL               | CRITICAL        |
| IAM finding             | HIGH                   | HIGH            |
| IAM finding             | MEDIUM                 | MEDIUM          |
| IAM finding             | LOW                    | LOW             |

**SCC `INACTIVE` filter.** Closed findings still come through the
reader (operators may want to see them); the normalizer drops
`state="INACTIVE"` records so the report shows only currently-active
posture issues.

**Finding-id construction:** `CSPM-GCP-{SCC|IAM}-{seq:03d}-{slug}`
matching F.3's `FINDING_ID_RE`. Per-project sequence counter so
finding IDs are stable within a run.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from shared.fabric.envelope import NexusEnvelope

from multi_cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    CSPMFindingType,
    Severity,
    build_finding,
    source_token,
)
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_gcp(
    *,
    scc: Sequence[GcpSccFinding] = (),
    iam: Sequence[GcpIamFinding] = (),
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> tuple[CloudPostureFinding, ...]:
    """Convert GCP reader outputs into OCSF 2003 Compliance Findings."""
    out: list[CloudPostureFinding] = []
    seq_by_proj: dict[tuple[str, str], int] = {}

    for scc_record in scc:
        seq_key = (scc_record.project_id, "SCC")
        seq_by_proj[seq_key] = seq_by_proj.get(seq_key, 0) + 1
        finding = _from_scc(
            scc_record,
            sequence=seq_by_proj[seq_key],
            envelope=envelope,
            scan_time=scan_time,
        )
        if finding is not None:
            out.append(finding)

    for iam_record in iam:
        seq_key = (iam_record.project_id, "IAM")
        seq_by_proj[seq_key] = seq_by_proj.get(seq_key, 0) + 1
        finding = _from_iam(
            iam_record,
            sequence=seq_by_proj[seq_key],
            envelope=envelope,
            scan_time=scan_time,
        )
        if finding is not None:
            out.append(finding)

    return tuple(out)


def _from_scc(
    record: GcpSccFinding,
    *,
    sequence: int,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> CloudPostureFinding | None:
    # Drop INACTIVE — those are closed findings; the reader keeps them so
    # operators can audit history, but the report should show only active.
    if record.state.upper() == "INACTIVE":
        return None
    severity = _scc_severity(record.severity)
    if severity is None:
        return None

    finding_id = _build_finding_id(
        source=CSPMFindingType.GCP_SCC,
        sequence=sequence,
        slug_seed=record.category,
    )
    rule_id = _slugify(record.category)[:32] or "scc"
    affected = [
        AffectedResource(
            cloud="gcp",
            account_id=record.project_id or "unknown",
            region="global",
            resource_type=_resource_type_from_name(record.resource_name),
            resource_id=record.resource_name,
            arn=record.resource_name,
        )
    ]
    return build_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title=f"{record.category} ({record.severity})",
        description=record.description or record.category,
        affected=affected,
        detected_at=record.detected_at or scan_time,
        envelope=envelope,
        evidence={
            "kind": "scc",
            "scc_category": record.category,
            "scc_severity": record.severity,
            "scc_state": record.state,
            "scc_parent": record.parent,
            "scc_external_uri": record.external_uri,
            "source_finding_name": record.finding_name,
            "source_finding_type": CSPMFindingType.GCP_SCC.value,
            "unmapped": record.unmapped,
        },
    )


def _from_iam(
    record: GcpIamFinding,
    *,
    sequence: int,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> CloudPostureFinding | None:
    severity = _iam_severity(record.severity)
    if severity is None:
        return None

    finding_id = _build_finding_id(
        source=CSPMFindingType.GCP_IAM,
        sequence=sequence,
        slug_seed=f"{record.role}-{record.member}",
    )
    rule_id = _slugify(record.role)[:32] or "iam"
    affected = [
        AffectedResource(
            cloud="gcp",
            account_id=record.project_id or "unknown",
            region="global",
            resource_type=record.asset_type or "GcpResource",
            resource_id=record.asset_name,
            arn=record.asset_name,
        )
    ]
    return build_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title=f"IAM: {record.role} → {record.member}",
        description=record.reason,
        affected=affected,
        detected_at=record.detected_at or scan_time,
        envelope=envelope,
        evidence={
            "kind": "iam",
            "role": record.role,
            "member": record.member,
            "asset_type": record.asset_type,
            "reason": record.reason,
            "source_finding_type": CSPMFindingType.GCP_IAM.value,
            "unmapped": record.unmapped,
        },
    )


# ---------------------------- severity mappings ---------------------------


_SCC_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "SEVERITY_UNSPECIFIED": Severity.INFO,
}


def _scc_severity(value: str) -> Severity | None:
    return _SCC_SEVERITY_MAP.get(value)


_IAM_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _iam_severity(value: str) -> Severity | None:
    return _IAM_SEVERITY_MAP.get(value)


# ---------------------------- helpers -------------------------------------


def _build_finding_id(
    *,
    source: CSPMFindingType,
    sequence: int,
    slug_seed: str,
) -> str:
    """Construct an F.3-shaped finding_id: `CSPM-GCP-<SVC>-<NNN>-<context>`."""
    src = source_token(source)
    context = _slugify(slug_seed)[:40] or "finding"
    return f"CSPM-GCP-{src}-{sequence:03d}-{context}"


def _slugify(value: str) -> str:
    """Lowercase + replace runs of non-alphanumerics with hyphens; strip leading/trailing."""
    low = value.lower()
    slug = _SLUG_RE.sub("-", low).strip("-")
    return slug or ""


def _resource_type_from_name(resource_name: str) -> str:
    """`//compute.googleapis.com/projects/.../instances/vm-1` → `compute.googleapis.com/Instance`.

    Falls back to `GcpResource` when the asset name doesn't follow the standard form.
    """
    if not resource_name:
        return "GcpResource"
    # Standard form: `//<service>.googleapis.com/<rest>`
    if resource_name.startswith("//"):
        tail = resource_name[2:]
        service_sep = tail.find("/")
        if service_sep == -1:
            return "GcpResource"
        service = tail[:service_sep]
        # Look for a kind hint after the last `/`.
        kind_segments = tail[service_sep + 1 :].split("/")
        # Common pattern: .../<resource-type>/<name>. The penultimate segment
        # often signals the resource kind.
        if len(kind_segments) >= 2:
            kind = kind_segments[-2]
            return f"{service}/{kind.title()}" if kind else service
        return service
    return "GcpResource"


__all__ = ["normalize_gcp"]
