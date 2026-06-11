"""Compliance schemas — re-export F.3's OCSF v1.3 Compliance Finding (class_uid 2003).

**Q1 resolution (per the D.6 plan).** D.6 emits the **identical wire shape** as
F.3 Cloud Posture (`class_uid 2003 Compliance Finding`). D.6 is the **3rd
re-exporter of F.3's 2003 schema** (after D.5 + multi-cloud-posture + k8s-
posture; F.3 itself is the original producer). The OCSF constants +
`Severity` enum + `AffectedResource` + `FindingsReport` are re-exported
verbatim; D.6 introduces its own `COMPLIANCE_FINDING_ID_RE` (CIS-namespaced)
and its own `build_finding` because F.3's regex is locked to CSPM-prefixed
finding ids.

Cross-agent OCSF inventory after D.6 (Compliance Finding family):

| Agent                | OCSF class_uid | Discriminator                            |
| -------------------- | -------------- | ---------------------------------------- |
| Cloud Posture (F.3)  | 2003           | rule_id (CSPM rule string)               |
| Data Security (D.5)  | 2003           | DataSecurityFindingType (4 enum buckets) |
| Multi-cloud (D.5')   | 2003           | per-cloud rule_id                        |
| K8s Posture (D.6')   | 2003           | per-control rule_id                      |
| **Compliance (D.6)** | **2003**       | **compliance_<framework>_<control_id>**  |

Re-exports from `cloud_posture.schemas`:

- `OCSF_*` constants (CLASS_UID = 2003, CLASS_NAME = "Compliance Finding").
- `Severity` enum + `severity_to_id` / `severity_from_id` helpers.
- `AffectedResource` (same 6-field shape: cloud / account_id / region /
  resource_type / resource_id / arn).
- `FindingsReport` aggregate (re-exported verbatim; D.6 fills it with
  ComplianceFinding-wrapped payloads).

D.6-specific additions:

- `COMPLIANCE_FINDING_ID_RE` — validates `COMPLIANCE-CIS_AWS_V3-<control_id>-NNN-<context>`.
- `ComplianceFramework` enum — v0.1 ships only `CIS_AWS_V3`; v0.2 adds
  SOC2 / PCI / HIPAA / NIST.
- `ControlLevel` enum — CIS Level 1 vs Level 2.
- `compliance_finding_type(framework, control_id)` — builds the stable
  `finding_info.types[0]` string.
- `compliance_type_token(framework)` — finding-id source-token helper.
- `severity_for_level(level, required=...)` — CIS Level x required-flag
  to Severity (the canonical table that Task 9's scorer enforces).
- `build_finding(...)` — D.6 OCSF 2003 constructor (D.6 regex).
- `ComplianceFinding` — typed wrapper over the wrapped OCSF dict.

Q6 reminder: this module carries no verbatim CIS Benchmark text. The
control_id strings (e.g., "1.1", "2.1.5") are public reference IDs and
are not licence-protected.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from cloud_posture.schemas import (
    OCSF_ACTIVITY_CREATE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_COMPLIANCE_FAILED_STATUS_ID,
    OCSF_STATUS_NEW,
    OCSF_VERSION,
    AffectedResource,
    FindingsReport,
    Severity,
    severity_from_id,
    severity_to_id,
)
from pydantic import BaseModel
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

# Compliance finding IDs:
# ``COMPLIANCE-<FRAMEWORK_TOKEN>-<CONTROL_TOKEN>-NNN-<context>``.
# - FRAMEWORK_TOKEN: uppercase ASCII (`CIS_AWS_V3`). Future v0.2 frameworks
#   land as new tokens (SOC2 / PCI_DSS_V4 / HIPAA / NIST_800_53_R5).
# - CONTROL_TOKEN: CIS dotted control id with `.` replaced by `_`
#   (e.g., "1.1" -> "1_1"; "2.1.5" -> "2_1_5"). The regex bracket
#   `[A-Z0-9_.]+` keeps `.` legal but `_` is the canonical form in v0.1.
# - NNN: 3-digit zero-padded sequence per-correlator.
# - context: lowercase slug ``[a-z0-9_.-]+``.
COMPLIANCE_FINDING_ID_RE = re.compile(r"^COMPLIANCE-[A-Z0-9_]+-[A-Z0-9_.]+-\d{3}-[a-z0-9_.-]+$")


class ComplianceFramework(StrEnum):
    """The compliance frameworks D.6 can map findings against.

    v0.1 ships only CIS_AWS_V3. v0.2 adds the rest per the plan §Q2.
    Renaming a value is a coordinated wire-shape change (downstream
    consumers may filter on the discriminator).
    """

    CIS_AWS_V3 = "cis_aws_v3"
    # v0.2 §Q2 — the rest of the CIS family (additive; the offline run()/eval emits only
    # CIS_AWS_V3, so byte-identity holds, WI-C5).
    CIS_AZURE_V2 = "cis_azure_v2"
    CIS_GCP_V2 = "cis_gcp_v2"
    CIS_K8S_V18 = "cis_k8s_v18"


class ControlLevel(StrEnum):
    """CIS Benchmark control level. Drives the canonical severity table.

    - LEVEL_1 controls are minimum-required posture; failures land at
      HIGH (if also flagged required) or MEDIUM (recommended).
    - LEVEL_2 controls are defense-in-depth; failures land at MEDIUM
      (required) or LOW (recommended).

    The exact mapping lives in :func:`severity_for_level`.
    """

    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"


_FRAMEWORK_TOKEN: dict[ComplianceFramework, str] = {
    ComplianceFramework.CIS_AWS_V3: "CIS_AWS_V3",
    ComplianceFramework.CIS_AZURE_V2: "CIS_AZURE_V2",
    ComplianceFramework.CIS_GCP_V2: "CIS_GCP_V2",
    ComplianceFramework.CIS_K8S_V18: "CIS_K8S_V18",
}


def compliance_type_token(framework: ComplianceFramework) -> str:
    """Return the FINDING_ID-safe uppercase token for a framework."""
    return _FRAMEWORK_TOKEN[framework]


def compliance_finding_type(framework: ComplianceFramework, control_id: str) -> str:
    """Build the stable ``finding_info.types[0]`` discriminator string.

    Example: ``compliance_cis_aws_v3_1_1``. Downstream consumers (D.7
    Investigation, Meta-Harness, auditor-export pipelines) filter on
    ``class_uid == 2003`` first then on this string to disambiguate
    D.6 emits from F.3 / D.5 / multi-cloud / k8s posture emits.
    """
    return f"compliance_{framework.value}_{_normalise_control_id(control_id)}"


def _normalise_control_id(control_id: str) -> str:
    """Replace CIS dot-separators with underscores for use inside identifiers.

    ``"1.1"`` -> ``"1_1"``; ``"2.1.5"`` -> ``"2_1_5"``.
    """
    return control_id.replace(".", "_")


def severity_for_level(level: ControlLevel, *, required: bool) -> Severity:
    """Canonical CIS Level x required-flag -> Severity table (Q9).

    Q9 reminder: Task 9's :mod:`compliance.scorer` is the single
    canonical source of severity. Correlators may emit at correlator-
    default; the scorer re-stamps via this function. Operators must
    be able to recompute severity from (level, required) by hand.
    """
    if level is ControlLevel.LEVEL_1:
        return Severity.HIGH if required else Severity.MEDIUM
    return Severity.MEDIUM if required else Severity.LOW


class ComplianceFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Compliance Finding dict (D.6 flavor).

    Construction validates that the payload is class_uid 2003, has a valid
    ``finding_info.uid`` matching ``COMPLIANCE_FINDING_ID_RE``, and carries a
    well-formed ``nexus_envelope``. The full wrapped payload is preserved
    for emission.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not COMPLIANCE_FINDING_ID_RE.match(finding_id):
            raise ValueError(
                f"finding_id must match {COMPLIANCE_FINDING_ID_RE.pattern} (got {finding_id!r})"
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
        """Return the framework-namespaced control identifier
        (e.g. ``cis_aws_v3:1.1``)."""
        return str(self._payload["compliance"]["control"])

    @property
    def finding_type(self) -> str:
        """Return the ``finding_info.types[0]`` discriminator string."""
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


# OCSF Compliance Finding status_id for a passing control (compliance-local; the OCSF
# standard pairs this with the imported FAILED status_id = 2). v0.2 Task 6 — PASS attestation.
OCSF_COMPLIANCE_PASSED_STATUS_ID = 1


class MissingPositiveEvidenceError(ValueError):
    """A PASS attestation lacked positive evidence (WI-C6 / pause-trigger #13)."""


def build_pass_finding(
    *,
    finding_id: str,
    framework: ComplianceFramework,
    control_id: str,
    title: str,
    description: str,
    affected: list[AffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    attestation: dict[str, Any],
) -> ComplianceFinding:
    """Build an OCSF 2003 Compliance Finding attesting a control **PASSED** (status_id 1).

    Mirrors `build_finding`'s wire shape but sets `compliance.status = "Passed"` and an
    INFO severity. Per **WI-C6 / pause-trigger #13** a PASS MUST carry **positive
    evidence** — ``attestation`` must be a non-empty dict (the proof the control holds, not
    merely the absence of a FAIL); an empty attestation raises."""
    if not COMPLIANCE_FINDING_ID_RE.match(finding_id):
        raise ValueError(
            f"finding_id must match {COMPLIANCE_FINDING_ID_RE.pattern} (got {finding_id!r})"
        )
    if not affected:
        raise ValueError("affected resources list must not be empty")
    if not attestation:
        raise MissingPositiveEvidenceError(
            f"PASS finding {finding_id!r} must include positive evidence (WI-C6)"
        )

    timestamp_ms = int(detected_at.timestamp() * 1000)
    rule_id = f"{framework.value}:{control_id}"
    payload: dict[str, Any] = {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{OCSF_CLASS_NAME}: Create",
        "severity_id": severity_to_id(Severity.INFO),
        "severity": Severity.INFO.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Nexus Compliance", "vendor_name": "Nexus Cyber OS"},
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
            "types": [compliance_finding_type(framework, control_id)],
        },
        "compliance": {
            "control": rule_id,
            "status": "Passed",
            "status_id": OCSF_COMPLIANCE_PASSED_STATUS_ID,
        },
        "resources": [r.to_ocsf() for r in affected],
        "evidences": [attestation],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return ComplianceFinding(wrapped)


def build_finding(
    *,
    finding_id: str,
    framework: ComplianceFramework,
    control_id: str,
    severity: Severity,
    title: str,
    description: str,
    affected: list[AffectedResource],
    detected_at: datetime,
    envelope: NexusEnvelope,
    evidence: dict[str, Any] | None = None,
) -> ComplianceFinding:
    """Build a Nexus OCSF v1.3 Compliance Finding (D.6 flavor) wrapped with NexusEnvelope.

    Mirrors F.3's ``build_finding`` shape but uses D.6's regex,
    ``finding_info.types[0] = compliance_finding_type(framework,
    control_id)``, and ``compliance.control = "<framework>:<control_id>"``.
    """
    if not COMPLIANCE_FINDING_ID_RE.match(finding_id):
        raise ValueError(
            f"finding_id must match {COMPLIANCE_FINDING_ID_RE.pattern} (got {finding_id!r})"
        )
    if not affected:
        raise ValueError("affected resources list must not be empty")

    timestamp_ms = int(detected_at.timestamp() * 1000)
    rule_id = f"{framework.value}:{control_id}"
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
                "name": "Nexus Compliance",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": {
            "uid": finding_id,
            "title": title,
            "desc": description,
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
            "types": [compliance_finding_type(framework, control_id)],
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
    return ComplianceFinding(wrapped)


class ControlMapping(BaseModel):
    """One mapping rule: how a source-finding shape maps to a CIS control.

    Lightweight typed record used by Tasks 6 + 7 correlators. The
    bundled control library (Task 4) carries a list of these per
    source-agent so the mapping table can be inspected + tested as
    data.
    """

    source_agent: str  # "cloud_posture" or "data_security"
    source_rule_id: str  # the F.3 / D.5 rule string this entry matches
    control_id: str  # CIS control id, e.g. "1.1" or "2.1.5"
    level: ControlLevel
    required: bool = True


__all__ = [
    "COMPLIANCE_FINDING_ID_RE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "AffectedResource",
    "ComplianceFinding",
    "ComplianceFramework",
    "ControlLevel",
    "ControlMapping",
    "FindingsReport",
    "Severity",
    "build_finding",
    "compliance_finding_type",
    "compliance_type_token",
    "severity_for_level",
    "severity_from_id",
    "severity_to_id",
]
