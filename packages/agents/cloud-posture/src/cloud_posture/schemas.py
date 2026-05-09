"""Cloud Posture finding schemas — OCSF v1.3 Compliance Finding (class_uid 2003).

Per ADR-004: the wire format on `findings.>` is a vanilla OCSF v1.3 event dict
with a single extra `nexus_envelope` key carrying cross-cutting metadata
(correlation_id, tenant_id, agent_id, nlah_version, model_pin,
charter_invocation_id). This module is a thin typing layer over that dict.

- `Severity` — our internal enum (info/low/medium/high/critical) used for
  building findings; round-trips to OCSF `severity_id` 1..5 (Fatal=6 collapses
  to critical on read).
- `AffectedResource` — typed builder for one row of OCSF `resources`.
- `build_finding(...)` — constructor that produces a wrapped OCSF event.
- `CloudPostureFinding` — typed accessor wrapper over the wrapped dict.
- `FindingsReport` — aggregate report metadata + list of OCSF dicts.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

FINDING_ID_RE = re.compile(r"^CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")

# OCSF v1.3 constants
OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2003  # Compliance Finding
OCSF_CLASS_NAME = "Compliance Finding"
OCSF_ACTIVITY_CREATE = 1
OCSF_STATUS_NEW = 1
OCSF_COMPLIANCE_FAILED_STATUS_ID = 2


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
# OCSF severity_id 6 (Fatal) collapses to our `critical` on read.
_ID_TO_SEVERITY: dict[int, Severity] = {
    **{v: k for k, v in _SEVERITY_TO_ID.items()},
    6: Severity.CRITICAL,
}


def severity_to_id(s: Severity) -> int:
    return _SEVERITY_TO_ID[s]


def severity_from_id(i: int) -> Severity:
    if i not in _ID_TO_SEVERITY:
        raise ValueError(f"unknown OCSF severity_id: {i}")
    return _ID_TO_SEVERITY[i]


class AffectedResource(BaseModel):
    """A single affected resource. Maps to one OCSF ResourceDetails row."""

    cloud: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    region: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    arn: str = Field(min_length=1)

    def to_ocsf(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "uid": self.arn,
            "cloud_partition": self.cloud,
            "region": self.region,
            "owner": {"account_uid": self.account_id},
        }


class CloudPostureFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Compliance Finding dict.

    Construction validates that the payload is class_uid 2003, has a valid
    `finding_info.uid` matching `FINDING_ID_RE`, and carries a well-formed
    `nexus_envelope`. The full wrapped payload is preserved for emission.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not FINDING_ID_RE.match(finding_id):
            raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
        # unwrap_ocsf raises if nexus_envelope is missing or malformed.
        unwrap_ocsf(payload)
        self._payload = payload

    @property
    def severity(self) -> Severity:
        return severity_from_id(int(self._payload["severity_id"]))

    @property
    def finding_id(self) -> str:
        return str(self._payload["finding_info"]["uid"])

    @property
    def rule_id(self) -> str:
        return str(self._payload["compliance"]["control"])

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
    def resources(self) -> list[dict[str, Any]]:
        return list(self._payload.get("resources", []))

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


def build_finding(
    *,
    finding_id: str,
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> CloudPostureFinding:
    """Build a Nexus OCSF v1.3 Compliance Finding wrapped with a NexusEnvelope.

    `finding_id` must match `FINDING_ID_RE` (`CSPM-<CLOUD>-<SVC>-<NNN>-<context>`).
    `affected` must contain at least one resource.
    """
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not affected:
        raise ValueError("affected resources list must not be empty")

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
                "name": "Nexus Cloud Posture",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
        },
        "compliance": {
            "control": rule_id,
            "status": "Failed",
            "status_id": OCSF_COMPLIANCE_FAILED_STATUS_ID,
        },
        "resources": [r.to_ocsf() for r in affected],
        "evidences": [evidence] if evidence else [],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return CloudPostureFinding(wrapped)


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by an agent invocation.

    `findings` stores raw wrapped OCSF dicts (one per CloudPostureFinding) so
    the report serializes cleanly to JSON without losing OCSF shape.
    """

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

    def add_finding(self, f: CloudPostureFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is None:
                continue
            counts[severity_from_id(int(sid)).value] += 1
        return counts
