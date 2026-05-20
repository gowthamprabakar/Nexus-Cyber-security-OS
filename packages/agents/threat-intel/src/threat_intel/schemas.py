"""Threat-intel schemas — re-export D.4's OCSF v1.3 Detection Finding (class_uid 2004).

**Q1 resolution (per the D.8 plan).** D.8 emits the **identical wire shape**
as D.4 Network Threat (`class_uid 2004 Detection Finding`). D.8 is the
**2nd re-exporter of D.4's 2004 schema** (D.4 itself is the 1st). The
OCSF constants + Severity enum are re-exported verbatim; D.8 introduces
its own `FINDING_ID_RE` (TI-prefixed) and its own `build_finding` because
D.4's regex is locked to network-detector finding types.

Cross-agent OCSF inventory after D.8 (Detection Finding family):

| Agent                  | OCSF class_uid | Discriminator              |
| ---------------------- | -------------- | -------------------------- |
| Network Threat (D.4)   | 2004           | FindingType (network)      |
| **Threat Intel (D.8)** | **2004**       | **ThreatIntelFindingType** |

Re-exports from `network_threat.schemas`:

- `OCSF_*` constants (CLASS_UID = 2004, CLASS_NAME = "Detection Finding").
- `Severity` enum + `severity_to_id` / `severity_from_id` helpers.

Re-exports from `cloud_posture.schemas`:

- `AffectedResource` — general-purpose resource model (matches D.5's
  re-export choice; cleaner than D.4's network-specific
  `AffectedNetwork` for non-network correlations).

D.8-specific additions:

- `THREAT_INTEL_FINDING_ID_RE` — validates ``TI-(CVE_KEV|IOC_NET|
  IOC_RUN|TECHNIQUE)-<token>-NNN-<context>``.
- `ThreatIntelFindingType` enum — 4 correlator discriminators.
- `IocType` enum — 5 IOC kinds (ip, domain, url, file_hash, cve_id).
- `source_token(finding_type)` — finding-id source-token helper.
- `build_finding(...)` — D.8 OCSF 2004 constructor (D.8 regex).
- `ThreatIntelFinding` — typed wrapper over the wrapped OCSF dict.
- `FindingsReport` — aggregate report metadata + list of OCSF dicts.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from cloud_posture.schemas import AffectedResource
from network_threat.schemas import (
    OCSF_ACTIVITY_CREATE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_STATUS_NEW,
    OCSF_VERSION,
    Severity,
    severity_from_id,
    severity_to_id,
)
from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

# Threat-intel finding IDs: ``TI-(CVE_KEV|IOC_NET|IOC_RUN|TECHNIQUE)-<token>-NNN-<context>``.
# Distinct from D.4's NETWORK- prefix; downstream consumers (D.7,
# Meta-Harness) filter on ``class_uid == 2004`` first and then on
# ``finding_info.types[0] == "threat_intel"`` to disambiguate.
THREAT_INTEL_FINDING_ID_RE = re.compile(
    r"^TI-(CVE_KEV|IOC_NET|IOC_RUN|TECHNIQUE)-[A-Z0-9_.]+-\d{3}-[a-z0-9_.-]+$"
)


class ThreatIntelFindingType(StrEnum):
    """The correlator-output discriminator. Drives ``finding_info.types[0]``.

    Per ADR-010 "When this template stops applying" rule: renaming a
    value here is a coordinated OCSF wire-shape change, not a within-
    agent extension. Downstream consumers (D.7 Investigation, Meta-
    Harness, A.1 Remediation) may filter on these strings.
    """

    CVE_IN_KEV_CATALOG = "threat_intel_cve_in_kev_catalog"
    IOC_MATCH_NETWORK = "threat_intel_ioc_match_network"
    IOC_MATCH_RUNTIME = "threat_intel_ioc_match_runtime"
    ATTACK_TECHNIQUE_OBSERVED = "threat_intel_attack_technique_observed"


class IocType(StrEnum):
    """The 5 IOC kinds the v0.1 classifier + correlators handle.

    Wire-format-stable strings — used inside the IOC index (Stage 2
    ENRICH) and inside finding evidence dicts.
    """

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    CVE_ID = "cve_id"


# Maps each correlator type to its FINDING_ID_RE source-token (the second
# bracket: ``TI-<TOKEN>-...``). These are stable wire strings.
_FT_SOURCE_TOKEN: dict[ThreatIntelFindingType, str] = {
    ThreatIntelFindingType.CVE_IN_KEV_CATALOG: "CVE_KEV",
    ThreatIntelFindingType.IOC_MATCH_NETWORK: "IOC_NET",
    ThreatIntelFindingType.IOC_MATCH_RUNTIME: "IOC_RUN",
    ThreatIntelFindingType.ATTACK_TECHNIQUE_OBSERVED: "TECHNIQUE",
}


def source_token(finding_type: ThreatIntelFindingType) -> str:
    """Return the FINDING_ID_RE source-token for a ``ThreatIntelFindingType``."""
    return _FT_SOURCE_TOKEN[finding_type]


class ThreatIntelFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Detection Finding dict (threat-intel flavor).

    Construction validates that the payload is class_uid 2004, has a
    valid ``finding_info.uid`` matching ``THREAT_INTEL_FINDING_ID_RE``,
    and carries a well-formed ``nexus_envelope``. The full wrapped
    payload is preserved for emission.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not THREAT_INTEL_FINDING_ID_RE.match(finding_id):
            raise ValueError(
                f"finding_id must match {THREAT_INTEL_FINDING_ID_RE.pattern} (got {finding_id!r})"
            )
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
        return str(self._payload["finding_info"]["types"][0])

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
    finding_type: ThreatIntelFindingType,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> ThreatIntelFinding:
    """Build a Nexus OCSF v1.3 Detection Finding (Threat Intel flavor) wrapped with NexusEnvelope.

    Mirrors D.4's ``build_finding`` shape but uses D.8's regex +
    `finding_info.types[0]` = the ThreatIntelFindingType value (e.g.,
    ``"threat_intel_cve_in_kev_catalog"``). ``finding_id`` must match
    ``THREAT_INTEL_FINDING_ID_RE``.
    """
    if not THREAT_INTEL_FINDING_ID_RE.match(finding_id):
        raise ValueError(
            f"finding_id must match {THREAT_INTEL_FINDING_ID_RE.pattern} (got {finding_id!r})"
        )
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
                "name": "Nexus Threat Intel",
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
        "resources": [r.to_ocsf() for r in affected],
        "evidences": [evidence] if evidence else [],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return ThreatIntelFinding(wrapped)


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by a Threat Intel agent invocation.

    Mirrors the FindingsReport shape used across other agents — F.3 /
    multi-cloud-posture / k8s-posture / D.5. ``findings`` stores raw
    wrapped OCSF dicts (one per ThreatIntelFinding) so the report
    serialises cleanly to JSON without losing OCSF shape.
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

    def add_finding(self, f: ThreatIntelFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is None:
                continue
            counts[severity_from_id(int(sid)).value] += 1
        return counts


__all__ = [
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "THREAT_INTEL_FINDING_ID_RE",
    "AffectedResource",
    "FindingsReport",
    "IocType",
    "Severity",
    "ThreatIntelFinding",
    "ThreatIntelFindingType",
    "build_finding",
    "severity_from_id",
    "severity_to_id",
    "source_token",
]
