"""Identity finding schemas — OCSF v1.3 Detection Finding (class_uid 2004).

**Q1 resolution (per the D.2 plan).** Identity findings are *detections of
risky state*, not compliance violations against a specific framework. The
right OCSF class is `class_uid 2004` Detection Finding (under
`category_uid 2` Findings) — not 2003 Compliance Finding (which CSPM uses
because Prowler maps to CIS / PCI / etc.).

Cross-agent OCSF inventory after D.2:

| Agent          | OCSF class_uid | Class name           |
| -------------- | -------------- | -------------------- |
| Cloud Posture  | 2003           | Compliance Finding   |
| Vulnerability  | 2002           | Vulnerability Finding |
| Identity (D.2) | 2004           | Detection Finding    |

Different classes are correct — they describe different finding shapes on
the wire. Downstream consumers (fabric, eval-framework, Meta-Harness) read
the `class_uid` and dispatch.

This module is a thin typing layer over the wire format, mirroring
[cloud-posture's `schemas.py`](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py)
+ [D.1 vulnerability's `schemas.py`](../../../packages/agents/vulnerability/src/vulnerability/schemas.py).

**ADR-007 v1.1 pattern check (D.2 risk-down):** the schema-as-typing-layer
pattern carries over verbatim — same Severity enum, same envelope wrap,
same FindingsReport shape. The only deltas are:

1. New `FindingType` enum (overprivilege / dormant / external_access /
   mfa_gap / admin_path) — domain-specific to Identity.
2. `AffectedPrincipal` instead of `AffectedResource` / `AffectedPackage`
   (identity findings live on principals, not cloud resources or packages).
3. `class_uid 2004` Detection Finding instead of 2003/2002.
4. `evidence` dict carries finding-type-specific context (e.g.,
   `days_dormant`, `attached_policies`, `trusts`).

Verdict: pattern generalizes; no ADR-007 amendment needed from this task.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

# Sentinel used by Identity findings that carry no CVE (most of them).
CVE_NA = "CVE-NA"

FINDING_ID_RE = re.compile(
    r"^IDENT-(OVERPRIV|DORMANT|EXTERNAL|MFA|ADMIN)-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$"
)

# OCSF v1.3 constants
OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2004  # Detection Finding
OCSF_CLASS_NAME = "Detection Finding"
OCSF_ACTIVITY_CREATE = 1
OCSF_STATUS_NEW = 1


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_TO_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_ID_TO_SEVERITY: dict[int, Severity] = {
    **{v: k for k, v in _SEVERITY_TO_ID.items()},
    6: Severity.CRITICAL,  # OCSF Fatal collapses to critical
}


def severity_to_id(s: Severity) -> int:
    return _SEVERITY_TO_ID[s]


def severity_from_id(i: int) -> Severity:
    if i not in _ID_TO_SEVERITY:
        raise ValueError(f"unknown OCSF severity_id: {i}")
    return _ID_TO_SEVERITY[i]


class FindingType(StrEnum):
    """Identity finding categories. Drives the second-letter code in finding_id."""

    OVERPRIVILEGE = "overprivilege"
    DORMANT = "dormant"
    EXTERNAL_ACCESS = "external_access"
    MFA_GAP = "mfa_gap"
    ADMIN_PATH = "admin_path"


# Map FindingType to the short token used inside finding_id (matches FINDING_ID_RE).
_FT_TOKEN: dict[FindingType, str] = {
    FindingType.OVERPRIVILEGE: "OVERPRIV",
    FindingType.DORMANT: "DORMANT",
    FindingType.EXTERNAL_ACCESS: "EXTERNAL",
    FindingType.MFA_GAP: "MFA",
    FindingType.ADMIN_PATH: "ADMIN",
}


# ---------------------------- AffectedPrincipal --------------------------


class AffectedPrincipal(BaseModel):
    """One IAM principal (User / Role / Group / FederatedUser) that the finding describes."""

    principal_type: str = Field(min_length=1)  # User / Role / Group / FederatedUser
    principal_name: str = Field(min_length=1)
    arn: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    last_used_at: datetime | None = None  # null = never used or unknown

    def to_ocsf(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type": self.principal_type,
            "name": self.principal_name,
            "uid": self.arn,
            "account": {"uid": self.account_id},
        }
        if self.last_used_at is not None:
            out["last_active_time"] = int(self.last_used_at.timestamp() * 1000)
        return out


# ---------------------------- IdentityFinding wrapper --------------------


class IdentityFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Detection Finding dict."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not FINDING_ID_RE.match(finding_id):
            raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
        unwrap_ocsf(payload)  # raises if envelope missing/malformed
        self._payload = payload

    @property
    def severity(self) -> Severity:
        return severity_from_id(int(self._payload["severity_id"]))

    @property
    def finding_id(self) -> str:
        return str(self._payload["finding_info"]["uid"])

    @property
    def title(self) -> str:
        return str(self._payload["finding_info"]["title"])

    @property
    def description(self) -> str:
        return str(self._payload["finding_info"]["desc"])

    @property
    def envelope(self) -> NexusEnvelope:
        _, env = unwrap_ocsf(self._payload)
        return env

    @property
    def finding_type(self) -> FindingType:
        return FindingType(str(self._payload["finding_info"]["types"][0]))

    @property
    def affected_principals(self) -> list[dict[str, Any]]:
        return list(self._payload.get("affected_principals", []))

    @property
    def principal_arns(self) -> list[str]:
        return [str(p.get("uid", "")) for p in self.affected_principals]

    @property
    def evidence(self) -> dict[str, Any]:
        evs = self._payload.get("evidences") or []
        if not evs:
            return {}
        first = evs[0]
        return dict(first) if isinstance(first, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


# ---------------------------- build_finding ------------------------------


def build_finding(
    *,
    finding_id: str,
    finding_type: FindingType,
    severity: Severity,
    title: str,
    description: str,
    affected_principals: list[AffectedPrincipal],
    evidence: dict[str, Any],
    detected_at: datetime,
    envelope: NexusEnvelope,
) -> IdentityFinding:
    """Build a Nexus OCSF v1.3 Detection Finding (Identity flavor) wrapped with NexusEnvelope.

    `finding_id` must match `FINDING_ID_RE`
    (`IDENT-<TYPE>-<PRINCIPAL_SHORT>-NNN-<context>`).
    `affected_principals` must be non-empty.
    `evidence` is finding-type-specific; preserved verbatim under OCSF
    `evidences[0]`. Common keys per type:

    - OVERPRIVILEGE: `attached_policies: list[str]`, `inline_admin: bool`.
    - DORMANT: `days_dormant: int`, `last_used_at: ISO-8601 str`.
    - EXTERNAL_ACCESS: `trusts: list[str]` (cross-account principals).
    - MFA_GAP: `actions_admin: list[str]`.
    - ADMIN_PATH: `path: list[str]` (transitive group memberships).
    """
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not affected_principals:
        raise ValueError("affected_principals list must not be empty")

    timestamp_ms = int(detected_at.timestamp() * 1000)
    payload: dict[str, Any] = {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{OCSF_CLASS_NAME}: Create",
        "severity_id": severity_to_id(severity),
        "severity": severity.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Nexus Identity",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
            "types": [finding_type.value],
        },
        "affected_principals": [p.to_ocsf() for p in affected_principals],
        "evidences": [dict(evidence)] if evidence else [],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return IdentityFinding(wrapped)


# ---------------------------- FindingsReport -----------------------------


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by an Identity Agent invocation."""

    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    scan_started_at: datetime
    scan_completed_at: datetime
    findings: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    def add_finding(self, f: IdentityFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is None:
                continue
            counts[severity_from_id(int(sid)).value] += 1
        return counts

    def count_by_finding_type(self) -> dict[str, int]:
        counts = dict.fromkeys((ft.value for ft in FindingType), 0)
        for raw in self.findings:
            types = raw.get("finding_info", {}).get("types") or []
            if types:
                ft_value = str(types[0])
                if ft_value in counts:
                    counts[ft_value] += 1
        return counts


# ---------------------------- helper for finding-id construction ---------


def short_principal_id(arn: str) -> str:
    """Extract a finding-id-safe identifier from an IAM ARN.

    `arn:aws:iam::111122223333:user/alice` → `ALICE` (uppercased name);
    falls back to a hash-suffix when the name has invalid characters.
    """
    name = arn.rsplit("/", 1)[-1] if "/" in arn else arn
    safe = re.sub(r"[^A-Za-z0-9]", "", name).upper()
    return safe or "UNKNOWN"


# Re-export the FindingType-token map for tests / introspection.
__all__ = [
    "CVE_NA",
    "FINDING_ID_RE",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "AffectedPrincipal",
    "FindingType",
    "FindingsReport",
    "IdentityFinding",
    "Severity",
    "build_finding",
    "severity_from_id",
    "severity_to_id",
    "short_principal_id",
]
