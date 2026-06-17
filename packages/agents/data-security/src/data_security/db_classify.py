"""DB classifier → OCSF 2003 finding builders (v0.4 Stage 1.2).

Pure (no cloud) builders that turn the DynamoDB content-classification labels and
the RDS posture records (from the ``scan_dynamodb`` / ``scan_rds_posture`` tools)
into OCSF 2003 Compliance Findings — mirroring the secrets-ingest pattern
(discriminator on ``evidence.source_finding_type`` + ``source_token`` in the
finding_id). Labels/violations only — no raw data values cross into evidence
(the Q6 privacy contract).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from data_security.schemas import (
    AffectedResource,
    CloudPostureFinding,
    DataSecurityFindingType,
    Severity,
    build_finding,
    source_token,
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")

#: DynamoDB data types that elevate a finding to HIGH (regulated / identity-grade).
_HIGH_RISK_LABELS = frozenset(
    {"ssn", "credit_card", "cvv", "track_data", "medical_record_number", "npi"}
)


def _context(target: str, fallback: str) -> str:
    return (_SLUG_RE.sub("-", target.lower()).strip("-") or fallback)[:40]


def dynamodb_to_findings(
    hits: dict[str, list[str]],
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[CloudPostureFinding]:
    """Map ``{table: [data-type labels]}`` → OCSF 2003 sensitive-data findings."""
    ft = DataSecurityFindingType.SENSITIVE_DATA_IN_DYNAMODB
    findings: list[CloudPostureFinding] = []
    for sequence, table in enumerate(sorted(hits)):
        data_types = sorted(hits[table])
        if not data_types:
            continue
        severity = (
            Severity.HIGH
            if any(label in _HIGH_RISK_LABELS for label in data_types)
            else Severity.MEDIUM
        )
        affected = AffectedResource(
            cloud="aws",
            account_id=envelope.tenant_id,
            region="unknown",  # the labels-only hits dict does not carry region
            resource_type="dynamodb-table",
            resource_id=table,
            arn=f"arn:aws:dynamodb:::table/{table}",
        )
        findings.append(
            build_finding(
                finding_id=f"CSPM-AWS-{source_token(ft)}-{sequence:03d}-{_context(table, 'table')}",
                rule_id="sensitive_data_in_dynamodb",
                severity=severity,
                title=f"Sensitive data classified in DynamoDB table {table}",
                description=(
                    f"DynamoDB table {table} contains data classified as "
                    f"{', '.join(data_types)} (labels only; sampled content not persisted)."
                ),
                affected=[affected],
                detected_at=detected_at,
                envelope=envelope,
                evidence={
                    "rule": "sensitive_data_in_dynamodb",
                    "source_finding_type": ft.value,
                    "data_types": data_types,
                    "table": table,
                    "source_agent": "data_security",
                },
            )
        )
    return findings


def rds_to_findings(
    records: list[dict[str, Any]],
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[CloudPostureFinding]:
    """Map RDS posture records → OCSF 2003 posture-violation findings."""
    ft = DataSecurityFindingType.RDS_POSTURE_VIOLATION
    findings: list[CloudPostureFinding] = []
    for sequence, record in enumerate(records):
        identifier = str(record.get("identifier", "")) or "unknown"
        kind = str(record.get("kind", "instance"))
        violations = [str(v) for v in record.get("violations") or []]
        if not violations:
            continue
        # public + unencrypted is the high-severity combination.
        severity = (
            Severity.HIGH
            if "publicly_accessible" in violations and "storage_not_encrypted" in violations
            else Severity.MEDIUM
        )
        affected = AffectedResource(
            cloud="aws",
            account_id=envelope.tenant_id,
            region=str(record.get("region", "")) or "unknown",
            resource_type=f"rds-{kind}",
            resource_id=identifier,
            arn=f"arn:aws:rds:::{kind}/{identifier}",
        )
        findings.append(
            build_finding(
                finding_id=f"CSPM-AWS-{source_token(ft)}-{sequence:03d}-{_context(identifier, 'rds')}",
                rule_id="rds_posture_violation",
                severity=severity,
                title=f"RDS {kind} {identifier} posture violation",
                description=(
                    f"RDS {kind} {identifier} has posture violations: {', '.join(violations)}."
                ),
                affected=[affected],
                detected_at=detected_at,
                envelope=envelope,
                evidence={
                    "rule": "rds_posture_violation",
                    "source_finding_type": ft.value,
                    "violations": violations,
                    "identifier": identifier,
                    "kind": kind,
                    "source_agent": "data_security",
                },
            )
        )
    return findings


__all__ = ["dynamodb_to_findings", "rds_to_findings"]
