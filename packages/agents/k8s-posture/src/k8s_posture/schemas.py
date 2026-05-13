"""Kubernetes posture schemas — re-export F.3's OCSF v1.3 Compliance Finding.

**Q1 resolution (per the D.6 plan).** D.6 emits the **identical wire shape**
as F.3 Cloud Posture + D.5 Multi-Cloud Posture (`class_uid 2003 Compliance
Finding`) — no fork, no duplication. D.5 set the precedent (first agent
to inherit rather than fork); D.6 follows verbatim.

Cross-agent OCSF inventory after D.6 (CSPM family):

| Agent                            | OCSF class_uid | Discriminator              |
| -------------------------------- | -------------- | -------------------------- |
| Cloud Posture (F.3) — AWS        | 2003           | (none — AWS only)          |
| Multi-Cloud Posture (D.5)        | 2003           | CSPMFindingType (4 buckets) |
| **Kubernetes Posture (D.6)**     | **2003**       | **K8sFindingType (3 buckets)** |

Re-exports from `cloud_posture.schemas`:
- `OCSF_*` constants
- `Severity` enum
- `AffectedResource` model
- `CloudPostureFinding` typed wrapper
- `build_finding` constructor
- `FindingsReport` aggregate
- `FINDING_ID_RE`

D.6-specific additions:
- `K8sFindingType` enum (3 discriminators, one per source feed)
- `K8sSeverity` mapping helpers per Q5 (kube-bench / Polaris / manifest)
- `short_workload_token` helper for finding_id construction
"""

from __future__ import annotations

import re
from enum import StrEnum

from cloud_posture.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
)


class K8sFindingType(StrEnum):
    """The source-feed discriminator. Drives `finding_info.types[0]`."""

    CIS = "cspm_k8s_cis"
    POLARIS = "cspm_k8s_polaris"
    MANIFEST = "cspm_k8s_manifest"


_FT_SOURCE_TOKEN: dict[K8sFindingType, str] = {
    K8sFindingType.CIS: "CIS",
    K8sFindingType.POLARIS: "POLARIS",
    K8sFindingType.MANIFEST: "MANIFEST",
}


def source_token(finding_type: K8sFindingType) -> str:
    """Return the finding-id source-token for a `K8sFindingType`."""
    return _FT_SOURCE_TOKEN[finding_type]


# ---------------------------- severity maps -------------------------------


def kube_bench_severity(status: str, *, severity_marker: str = "") -> Severity | None:
    """Map a kube-bench result status → OCSF Severity (per Q5).

    `status`: FAIL / WARN / PASS / INFO (CIS test outcome).
    `severity_marker`: optional `severity: critical` marker from
    upstream-flagged controls (some CIS profiles override).
    Returns None for PASS / INFO — those aren't findings.
    """
    if severity_marker.lower() == "critical":
        return Severity.CRITICAL
    s = status.upper()
    if s == "FAIL":
        return Severity.HIGH
    if s == "WARN":
        return Severity.MEDIUM
    return None  # PASS / INFO / unknown → drop


def polaris_severity(severity: str) -> Severity | None:
    """Map a Polaris severity string → OCSF Severity (per Q5).

    `severity`: danger / warning / ignore.
    Returns None for `ignore` — those aren't findings.
    """
    s = severity.lower()
    if s == "danger":
        return Severity.HIGH
    if s == "warning":
        return Severity.MEDIUM
    return None  # ignore / unknown → drop


# Manifest-rule severity is fixed per rule (per Q5); the manifest reader
# attaches the severity directly to each finding it emits, so no map
# helper is needed here — the rule table lives in `tools/manifests.py`.


# ---------------------------- helpers -------------------------------------


def short_workload_token(namespace: str, workload: str) -> str:
    """Extract a finding-id-safe token from a (namespace, workload) pair.

    Replaces non-alphanumerics with empty string; uppercase; takes the last 12
    chars (so distinct workload names with long-prefix differences still
    distinguish).
    """
    combined = f"{namespace}{workload}"
    safe = re.sub(r"[^A-Za-z0-9]", "", combined).upper()
    if not safe:
        return "UNKNOWN"
    return safe[-12:] if len(safe) >= 12 else safe


__all__ = [
    "FINDING_ID_RE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "AffectedResource",
    "CloudPostureFinding",
    "FindingsReport",
    "K8sFindingType",
    "Severity",
    "build_finding",
    "kube_bench_severity",
    "polaris_severity",
    "severity_from_id",
    "severity_to_id",
    "short_workload_token",
    "source_token",
]
