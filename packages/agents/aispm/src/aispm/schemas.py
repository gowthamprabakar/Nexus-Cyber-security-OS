"""AI-SPM finding schemas — OCSF v1.3 (ADR-020).

D.11 AI-SPM emits **two** OCSF classes (operator Q3, formalized in ADR-020):

- **2003 Compliance Finding** — deployment-discovery *posture* (public endpoint, no VPC,
  logging off, no guardrail, …). Mirrors the fleet's posture agents.
- **2004 Detection Finding** — *prompt-injection* exposure surfaced by an active red-team
  probe (Garak). Mirrors the detection agents (D.2/D.3/D.4).

Self-contained (appsec/SSPM pattern), AI-native resources; depends only on
``shared.fabric.envelope`` + pydantic. ``finding_id`` ``AISPM-<PROVIDER>-<NNN>-<context>``;
the per-finding discriminator is ``finding_info.types[0]``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

FINDING_ID_RE = re.compile(r"^AISPM-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")

OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_COMPLIANCE_CLASS_UID = 2003  # posture (discovery)
OCSF_DETECTION_CLASS_UID = 2004  # prompt-injection
OCSF_ACTIVITY_CREATE = 1
OCSF_STATUS_NEW = 1
OCSF_COMPLIANCE_FAILED_STATUS_ID = 2
_VALID_CLASS_UIDS = frozenset({OCSF_COMPLIANCE_CLASS_UID, OCSF_DETECTION_CLASS_UID})


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
    6: Severity.CRITICAL,
}


def severity_to_id(s: Severity) -> int:
    return _SEVERITY_TO_ID[s]


def severity_from_id(i: int) -> Severity:
    if i not in _ID_TO_SEVERITY:
        raise ValueError(f"unknown OCSF severity_id: {i}")
    return _ID_TO_SEVERITY[i]


class AiAffectedResource(BaseModel):
    """A single affected AI resource. Maps to one OCSF ``resources`` row."""

    provider: str = Field(min_length=1)  # "bedrock" | "sagemaker" | "azure_openai" | "vertex"
    account_id: str = Field(min_length=1)  # cloud account / subscription / project
    resource_type: str = Field(min_length=1)  # "ai_service" | "ai_model" | "endpoint" | ...
    resource_id: str = Field(min_length=1)  # provider-native id / ARN

    def to_ocsf(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "uid": f"{self.provider}:{self.account_id}:{self.resource_id}",
            "data": {"provider": self.provider, "account_id": self.account_id},
        }


class AiFinding:
    """Typed wrapper over a wrapped OCSF v1.3 finding dict (class_uid 2003 or 2004)."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") not in _VALID_CLASS_UIDS:
            raise ValueError(
                f"expected OCSF class_uid in {sorted(_VALID_CLASS_UIDS)}, "
                f"got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not FINDING_ID_RE.match(finding_id):
            raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
        unwrap_ocsf(payload)
        self._payload = payload

    @property
    def class_uid(self) -> int:
        return int(self._payload["class_uid"])

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
    def envelope(self) -> NexusEnvelope:
        _, env = unwrap_ocsf(self._payload)
        return env

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


def _base_payload(
    *,
    class_uid: int,
    class_name: str,
    finding_id: str,
    finding_type: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AiAffectedResource],
    detected_at: datetime,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not finding_type:
        raise ValueError("finding_type (the discriminator) must not be empty")
    if not affected:
        raise ValueError("affected resources list must not be empty")
    timestamp_ms = int(detected_at.timestamp() * 1000)
    return {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": class_uid,
        "class_name": class_name,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": class_uid * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{class_name}: Create",
        "severity_id": severity_to_id(severity),
        "severity": severity.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Nexus AI Posture", "vendor_name": "Nexus Cyber OS"},
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "types": [finding_type],
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
        },
        "resources": [r.to_ocsf() for r in affected],
        "evidences": [evidence] if evidence else [],
    }


def build_posture_finding(
    *,
    finding_id: str,
    rule_id: str,
    finding_type: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AiAffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> AiFinding:
    """Build an OCSF 2003 Compliance Finding (deployment-discovery posture)."""
    payload = _base_payload(
        class_uid=OCSF_COMPLIANCE_CLASS_UID,
        class_name="Compliance Finding",
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=detected_at,
        evidence=evidence,
    )
    payload["compliance"] = {
        "control": rule_id,
        "status": "Failed",
        "status_id": OCSF_COMPLIANCE_FAILED_STATUS_ID,
    }
    return AiFinding(wrap_ocsf(payload, envelope))


def build_detection_finding(
    *,
    finding_id: str,
    finding_type: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AiAffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> AiFinding:
    """Build an OCSF 2004 Detection Finding (prompt-injection exposure)."""
    payload = _base_payload(
        class_uid=OCSF_DETECTION_CLASS_UID,
        class_name="Detection Finding",
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        detected_at=detected_at,
        evidence=evidence,
    )
    return AiFinding(wrap_ocsf(payload, envelope))


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by an AI-SPM invocation."""

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

    def add_finding(self, f: AiFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is not None:
                counts[severity_from_id(int(sid)).value] += 1
        return counts
