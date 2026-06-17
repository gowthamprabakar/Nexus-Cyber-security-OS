"""SSPM finding schemas — OCSF v1.3 Compliance Finding (class_uid 2003).

D.10 SSPM is a posture-class agent (operator Q2: OCSF 2003, matching the fleet's
posture agents). Per ADR-004 the wire format on ``findings.>`` is a vanilla OCSF v1.3
event dict with a single ``nexus_envelope`` key. Self-contained (appsec pattern) —
SaaS-native resources rather than the cloud-shaped ``AffectedResource``; depends only on
``shared.fabric.envelope`` + pydantic.

- ``Severity`` — internal enum; round-trips to OCSF ``severity_id`` 1..5.
- ``SaaSAffectedResource`` — typed builder for one OCSF ``resources`` row (provider/tenant).
- ``build_finding(...)`` — constructs a wrapped OCSF 2003 event with the per-finding
  ``finding_info.types[0]`` discriminator (a connector's ``finding_type`` token).
- ``SaaSFinding`` — typed accessor wrapper over the wrapped dict.
- ``FindingsReport`` — aggregate metadata + list of OCSF dicts.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

#: SSPM finding id: ``SSPM-<PROVIDER>-<NNN>-<context>`` (e.g. ``SSPM-GITHUB-001-acme-org``).
FINDING_ID_RE = re.compile(r"^SSPM-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")

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
_ID_TO_SEVERITY: dict[int, Severity] = {
    **{v: k for k, v in _SEVERITY_TO_ID.items()},
    6: Severity.CRITICAL,  # OCSF Fatal collapses to critical on read.
}


def severity_to_id(s: Severity) -> int:
    return _SEVERITY_TO_ID[s]


def severity_from_id(i: int) -> Severity:
    if i not in _ID_TO_SEVERITY:
        raise ValueError(f"unknown OCSF severity_id: {i}")
    return _ID_TO_SEVERITY[i]


class SaaSAffectedResource(BaseModel):
    """A single affected SaaS resource. Maps to one OCSF ``resources`` row."""

    provider: str = Field(min_length=1)  # "github" | "m365" | "slack"
    tenant_id: str = Field(min_length=1)  # the SaaS org/tenant id
    resource_type: str = Field(min_length=1)  # "saas_tenant" | "oauth_app" | "repository" | ...
    resource_id: str = Field(min_length=1)  # provider-native id

    def to_ocsf(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "uid": f"{self.provider}:{self.tenant_id}:{self.resource_id}",
            "data": {"provider": self.provider, "tenant_id": self.tenant_id},
        }


class SaaSFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Compliance Finding dict (class_uid 2003)."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not FINDING_ID_RE.match(finding_id):
            raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
        unwrap_ocsf(payload)  # raises if nexus_envelope missing/malformed
        self._payload = payload

    @property
    def severity(self) -> Severity:
        return severity_from_id(int(self._payload["severity_id"]))

    @property
    def finding_id(self) -> str:
        return str(self._payload["finding_info"]["uid"])

    @property
    def finding_type(self) -> str:
        types = self._payload["finding_info"].get("types", [])
        return str(types[0]) if types else ""

    @property
    def rule_id(self) -> str:
        return str(self._payload["compliance"]["control"])

    @property
    def envelope(self) -> NexusEnvelope:
        _, env = unwrap_ocsf(self._payload)
        return env

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


def build_finding(
    *,
    finding_id: str,
    rule_id: str,
    finding_type: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[SaaSAffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> SaaSFinding:
    """Build a Nexus OCSF v1.3 Compliance Finding (2003) wrapped with a NexusEnvelope.

    ``finding_id`` must match :data:`FINDING_ID_RE`. ``finding_type`` is the stable
    per-connector discriminator wired into ``finding_info.types[0]`` (e.g.
    ``"sspm_github_org_2fa_disabled"``). ``affected`` must be non-empty.
    """
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not finding_type:
        raise ValueError("finding_type (the discriminator) must not be empty")
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
            "product": {"name": "Nexus SaaS Posture", "vendor_name": "Nexus Cyber OS"},
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "types": [finding_type],
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
    return SaaSFinding(wrap_ocsf(payload, envelope))


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by an SSPM invocation.

    ``findings`` stores raw wrapped OCSF dicts (one per :class:`SaaSFinding`) so the
    report serializes cleanly to JSON without losing OCSF shape.
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

    def add_finding(self, f: SaaSFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is not None:
                counts[severity_from_id(int(sid)).value] += 1
        return counts
