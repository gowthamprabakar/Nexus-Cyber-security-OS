"""`normalize_azure` — Azure raw records → OCSF 2003 Compliance Findings.

Pure-function normalizer (no I/O, no async). Takes the typed reader
outputs from `tools/azure_defender.py` and `tools/azure_activity.py`
and produces a tuple of `CloudPostureFinding` (re-exported from F.3
via `schemas.py`).

**Severity mapping:**

| Source                    | Source value         | OCSF `Severity` |
| ------------------------- | -------------------- | --------------- |
| Defender assessment/alert | Critical             | CRITICAL        |
| Defender assessment/alert | High                 | HIGH            |
| Defender assessment/alert | Medium               | MEDIUM          |
| Defender assessment/alert | Low                  | LOW             |
| Defender assessment/alert | Informational        | INFO            |
| Activity Log              | Critical / Error     | HIGH            |
| Activity Log              | Warning              | MEDIUM          |
| Activity Log              | Informational / Verbose | INFO         |

**Activity-Log filter.** Not every Activity Log record is a finding —
only entries that suggest a configuration change worth highlighting.
v0.1 filters to:

- IAM operations (role assignments / policy changes)
- Network operations (NSG / VNet writes)
- Storage operations (storageAccounts writes)
- KeyVault operations (vault / secret writes)

Operations classified as `compute` or `other` are dropped — they're
typically benign at the activity-log level (start/stop VM is normal).
Phase 1c adds optional behavioural anomaly detection.

**Finding-id construction:** `CSPM-AZURE-{DEFENDER|ACTIVITY}-{seq:03d}-{slug}`
matching F.3's `FINDING_ID_RE`. Per-subscription sequence counter so
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
from multi_cloud_posture.tools.azure_activity import AzureActivityRecord
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_azure(
    *,
    defender: Sequence[AzureDefenderFinding] = (),
    activity: Sequence[AzureActivityRecord] = (),
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> tuple[CloudPostureFinding, ...]:
    """Convert Azure reader outputs into OCSF 2003 Compliance Findings."""
    out: list[CloudPostureFinding] = []
    seq_by_sub: dict[tuple[str, str], int] = {}

    for defender_record in defender:
        seq_key = (defender_record.subscription_id, "DEFENDER")
        seq_by_sub[seq_key] = seq_by_sub.get(seq_key, 0) + 1
        finding = _from_defender(
            defender_record,
            sequence=seq_by_sub[seq_key],
            envelope=envelope,
            scan_time=scan_time,
        )
        if finding is not None:
            out.append(finding)

    for activity_record in activity:
        seq_key = (activity_record.subscription_id, "ACTIVITY")
        seq_by_sub[seq_key] = seq_by_sub.get(seq_key, 0) + 1
        finding = _from_activity(
            activity_record,
            sequence=seq_by_sub[seq_key],
            envelope=envelope,
            scan_time=scan_time,
        )
        if finding is not None:
            out.append(finding)

    return tuple(out)


def _from_defender(
    record: AzureDefenderFinding,
    *,
    sequence: int,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> CloudPostureFinding | None:
    severity = _defender_severity(record.severity)
    if severity is None:
        return None

    # Healthy assessments are not findings.
    if record.kind == "assessment" and record.status.lower() == "healthy":
        return None

    finding_id = _build_finding_id(
        cloud="AZURE",
        source=CSPMFindingType.AZURE_DEFENDER,
        sequence=sequence,
        slug_seed=record.display_name,
    )
    rule_id = _last_segment(record.record_id) or _slugify(record.display_name)[:32]
    resource_id = record.resource_id or record.record_id
    affected = [
        AffectedResource(
            cloud="azure",
            account_id=record.subscription_id or "unknown",
            region="global",
            resource_type=_resource_type_from_id(resource_id),
            resource_id=resource_id,
            arn=resource_id,
        )
    ]
    return build_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title=record.display_name,
        description=record.description or record.display_name,
        affected=affected,
        detected_at=record.detected_at or scan_time,
        envelope=envelope,
        evidence={
            "kind": record.kind,
            "status": record.status,
            "assessment_type": record.assessment_type,
            "source_record_id": record.record_id,
            "source_finding_type": CSPMFindingType.AZURE_DEFENDER.value,
            "unmapped": record.unmapped,
        },
    )


def _from_activity(
    record: AzureActivityRecord,
    *,
    sequence: int,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> CloudPostureFinding | None:
    # Filter to the four operation classes worth flagging at the activity-log layer.
    if record.operation_class not in {"iam", "network", "storage", "keyvault"}:
        return None
    severity = _activity_severity(record.level)
    if severity is None:
        return None

    finding_id = _build_finding_id(
        cloud="AZURE",
        source=CSPMFindingType.AZURE_ACTIVITY,
        sequence=sequence,
        slug_seed=record.operation_name,
    )
    rule_id = _slugify(record.operation_name)[:32] or "activity"
    resource_id = record.resource_id or record.record_id
    affected = [
        AffectedResource(
            cloud="azure",
            account_id=record.subscription_id or "unknown",
            region="global",
            resource_type=_resource_type_from_id(resource_id),
            resource_id=resource_id,
            arn=resource_id,
        )
    ]
    return build_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title=f"{record.operation_name} ({record.status or record.category})",
        description=(
            f"Activity-Log operation {record.operation_name!r} (class {record.operation_class}) "
            f"in subscription {record.subscription_id or 'unknown'} by {record.caller or 'unknown'}."
        ),
        affected=affected,
        detected_at=record.detected_at or scan_time,
        envelope=envelope,
        evidence={
            "kind": "activity",
            "operation_class": record.operation_class,
            "operation_name": record.operation_name,
            "category": record.category,
            "level": record.level,
            "status": record.status,
            "caller": record.caller,
            "resource_group": record.resource_group,
            "source_record_id": record.record_id,
            "source_finding_type": CSPMFindingType.AZURE_ACTIVITY.value,
            "unmapped": record.unmapped,
        },
    )


# ---------------------------- severity mappings ---------------------------


_DEFENDER_SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


def _defender_severity(value: str) -> Severity | None:
    return _DEFENDER_SEVERITY_MAP.get(value)


_ACTIVITY_LEVEL_MAP: dict[str, Severity] = {
    "Critical": Severity.HIGH,  # Activity Critical is operational, not security-critical
    "Error": Severity.HIGH,
    "Warning": Severity.MEDIUM,
    "Informational": Severity.INFO,
    "Verbose": Severity.INFO,
}


def _activity_severity(level: str) -> Severity | None:
    return _ACTIVITY_LEVEL_MAP.get(level, Severity.INFO)


# ---------------------------- helpers -------------------------------------


def _build_finding_id(
    *,
    cloud: str,
    source: CSPMFindingType,
    sequence: int,
    slug_seed: str,
) -> str:
    """Construct an F.3-shaped finding_id: `CSPM-<CLOUD>-<SVC>-<NNN>-<context>`."""
    src = source_token(source)
    context = _slugify(slug_seed)[:40] or "finding"
    return f"CSPM-{cloud}-{src}-{sequence:03d}-{context}"


def _slugify(value: str) -> str:
    """Lowercase + replace runs of non-alphanumerics with hyphens; strip leading/trailing."""
    low = value.lower()
    slug = _SLUG_RE.sub("-", low).strip("-")
    return slug or ""


def _last_segment(record_id: str) -> str:
    """`/subscriptions/x/.../assessments/<rule>` → `<rule>` (used as rule_id)."""
    tail = record_id.rstrip("/").split("/")[-1] if record_id else ""
    return tail or "rule"


def _resource_type_from_id(resource_id: str) -> str:
    """`/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1`
    → `Microsoft.Storage/storageAccounts`. Falls back to `AzureResource`.
    """
    if not resource_id:
        return "AzureResource"
    parts = resource_id.split("/providers/")
    if len(parts) < 2:
        return "AzureResource"
    tail = parts[1].split("/")
    if len(tail) >= 2:
        return f"{tail[0]}/{tail[1]}"
    return tail[0] if tail else "AzureResource"


__all__ = ["normalize_azure"]
