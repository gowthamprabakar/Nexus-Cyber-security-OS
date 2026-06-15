"""OCSF 2003 Compliance Finding emission for AppSec (D.14, B-1 PR2).

IaC misconfigurations (and later SAST/secrets) are policy/benchmark violations →
OCSF **class_uid 2003 Compliance Finding** (operator-confirmed; matches the posture
fleet — cloud-posture / k8s-posture / compliance / data-security all emit 2003 with
a discriminator). The discriminator rides ``finding_info.types[0]`` +
``evidence.source_finding_type`` (the fleet convention); ``compliance.control`` is
the scanner rule id (e.g. a Checkov ``CKV_*``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from appsec.schemas import AppSecFinding, Severity

OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2
OCSF_CLASS_UID = 2003
OCSF_CLASS_NAME = "Compliance Finding"
OCSF_ACTIVITY_CREATE = 1

_SEVERITY_TO_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def severity_to_id(severity: Severity) -> int:
    return _SEVERITY_TO_ID[severity]


def finding_to_ocsf(
    finding: AppSecFinding,
    *,
    customer_id: str,
    run_id: str,
    detected_at: datetime,
) -> dict[str, Any]:
    """Render one ``AppSecFinding`` as an OCSF 2003 Compliance Finding dict."""
    timestamp_ms = int(detected_at.timestamp() * 1000)
    return {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": "Findings",
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{OCSF_CLASS_NAME}: Create",
        "severity_id": severity_to_id(finding.severity),
        "severity": finding.severity.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": 1,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Nexus AppSec", "vendor_name": "Nexus Cyber OS"},
            "tenant_uid": customer_id,
            "correlation_uid": run_id,
        },
        "finding_info": {
            "uid": finding.finding_id,
            "title": finding.title,
            "desc": finding.description,
            "types": [finding.finding_type.value],
            "first_seen_time": timestamp_ms,
            "last_seen_time": timestamp_ms,
        },
        "compliance": {
            "control": finding.rule_id,
            "status": "Failed",
            "status_id": 3,
        },
        "resources": [
            {
                "type": "repository-file",
                "uid": f"{finding.repo_slug}/{finding.location}"
                if finding.location
                else finding.repo_slug,
                "name": finding.repo_slug,
            }
        ],
        "evidences": [
            {
                "source_finding_type": finding.finding_type.value,
                "rule_id": finding.rule_id,
                "repo": finding.repo_slug,
                "location": finding.location,
            }
        ],
    }


__all__ = ["OCSF_CLASS_UID", "finding_to_ocsf", "severity_to_id"]
