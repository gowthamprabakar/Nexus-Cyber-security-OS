"""`normalize_polaris` — Polaris raw findings → OCSF 2003 Compliance Findings.

Pure-function normalizer (no I/O, no async). Takes the typed reader
output from `tools/polaris.py` and produces a tuple of
`CloudPostureFinding` (re-exported from F.3 via `schemas.py`).

**Severity mapping** (per Q5):

| Source value | OCSF `Severity` |
| ------------ | --------------- |
| `danger`     | HIGH            |
| `warning`    | MEDIUM          |

`ignore` and unknown values are filtered by the reader; this normalizer
only sees danger/warning records.

**Finding-id construction:** `CSPM-KUBERNETES-POLARIS-{seq:03d}-{slug}`
where `slug` carries the Polaris check_id (e.g. `runasrootallowed`).
Per-namespace sequence counter so finding IDs are stable within a run.

**Resource shape** — Polaris findings describe a workload (and possibly
a specific container). The OCSF `AffectedResource` carries:

- `cloud = "kubernetes"`
- `account_id = <namespace>`
- `region = "cluster"`
- `resource_type = <workload_kind>` (Deployment / Pod / StatefulSet / ...)
- `resource_id = "<namespace>/<workload_name>[/<container_name>]"`
- `arn = "k8s://workload/<namespace>/<kind>/<name>[#<container>]"`
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from shared.fabric.envelope import NexusEnvelope

from k8s_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    K8sFindingType,
    build_finding,
    polaris_severity,
    source_token,
)
from k8s_posture.tools.polaris import PolarisFinding

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_polaris(
    findings: Sequence[PolarisFinding],
    *,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> tuple[CloudPostureFinding, ...]:
    """Convert Polaris reader outputs into OCSF 2003 Compliance Findings."""
    out: list[CloudPostureFinding] = []
    seq_by_ns: dict[str, int] = {}

    for record in findings:
        severity = polaris_severity(record.severity)
        if severity is None:
            continue

        ns_key = record.namespace or "default"
        seq_by_ns[ns_key] = seq_by_ns.get(ns_key, 0) + 1
        sequence = seq_by_ns[ns_key]

        finding_id = _build_finding_id(sequence=sequence, slug_seed=record.check_id)
        rule_id = record.check_id

        resource_id = f"{ns_key}/{record.workload_name}"
        arn = f"k8s://workload/{ns_key}/{record.workload_kind}/{record.workload_name}"
        if record.container_name:
            resource_id = f"{resource_id}/{record.container_name}"
            arn = f"{arn}#{record.container_name}"

        affected = [
            AffectedResource(
                cloud="kubernetes",
                account_id=ns_key,
                region="cluster",
                resource_type=record.workload_kind,
                resource_id=resource_id,
                arn=arn,
            )
        ]
        finding = build_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=f"{record.check_id}: {record.message}",
            description=record.message,
            affected=affected,
            detected_at=record.detected_at or scan_time,
            envelope=envelope,
            evidence={
                "kind": "polaris",
                "check_id": record.check_id,
                "check_level": record.check_level,
                "message": record.message,
                "polaris_severity": record.severity,
                "category": record.category,
                "workload_kind": record.workload_kind,
                "workload_name": record.workload_name,
                "namespace": record.namespace,
                "container_name": record.container_name,
                "source_finding_type": K8sFindingType.POLARIS.value,
                "unmapped": record.unmapped,
            },
        )
        out.append(finding)
    return tuple(out)


# ---------------------------- helpers -------------------------------------


def _build_finding_id(*, sequence: int, slug_seed: str) -> str:
    """Construct an F.3-shaped finding_id: `CSPM-KUBERNETES-POLARIS-NNN-<slug>`."""
    src = source_token(K8sFindingType.POLARIS)
    context = _slugify(slug_seed)[:40] or "polaris"
    return f"CSPM-KUBERNETES-{src}-{sequence:03d}-{context}"


def _slugify(value: str) -> str:
    """Lowercase + replace runs of non-alphanumerics with hyphens; strip leading/trailing."""
    low = value.lower()
    slug = _SLUG_RE.sub("-", low).strip("-")
    return slug or ""


__all__ = ["normalize_polaris"]
