"""`normalize_manifest` — manifest static-analysis findings → OCSF 2003.

Pure-function normalizer (no I/O, no async). Takes the typed reader
output from `tools/manifests.py` and produces a tuple of
`CloudPostureFinding` (re-exported from F.3 via `schemas.py`).

**Severity** is pre-graded per rule by the reader (per Q5 of the plan);
this normalizer lifts the rule's severity verbatim.

**Finding-id construction:** `CSPM-KUBERNETES-MANIFEST-{seq:03d}-{slug}`
where `slug` carries `<rule_id>-<workload_name>` (so the same rule on
distinct workloads yields distinct IDs even within a namespace bucket).
Per-(namespace, rule_id) sequence counter so finding IDs are stable
within a run.

**Resource shape** — manifest findings describe a workload (and possibly
a specific container). The OCSF `AffectedResource` carries:

- `cloud = "kubernetes"`
- `account_id = <namespace>`
- `region = "cluster"`
- `resource_type = <workload_kind>` (Deployment / Pod / CronJob / ...)
- `resource_id = "<namespace>/<workload_name>[/<container_name>]"`
- `arn = "k8s://manifest/<namespace>/<kind>/<name>[#<container>]"`
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
    source_token,
)
from k8s_posture.tools.manifests import ManifestFinding

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_manifest(
    findings: Sequence[ManifestFinding],
    *,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> tuple[CloudPostureFinding, ...]:
    """Convert manifest-analyser outputs into OCSF 2003 Compliance Findings."""
    out: list[CloudPostureFinding] = []
    seq_by_bucket: dict[tuple[str, str], int] = {}

    for record in findings:
        ns_key = record.namespace or "default"
        bucket = (ns_key, record.rule_id)
        seq_by_bucket[bucket] = seq_by_bucket.get(bucket, 0) + 1
        sequence = seq_by_bucket[bucket]

        slug_seed = f"{record.rule_id}-{record.workload_name}"
        finding_id = _build_finding_id(sequence=sequence, slug_seed=slug_seed)

        resource_id = f"{ns_key}/{record.workload_name}"
        arn = f"k8s://manifest/{ns_key}/{record.workload_kind}/{record.workload_name}"
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
            rule_id=record.rule_id,
            severity=record.severity,
            title=f"{record.rule_id}: {record.rule_title}",
            description=record.rule_title,
            affected=affected,
            detected_at=record.detected_at or scan_time,
            envelope=envelope,
            evidence={
                "kind": "manifest",
                "rule_id": record.rule_id,
                "rule_title": record.rule_title,
                "workload_kind": record.workload_kind,
                "workload_name": record.workload_name,
                "namespace": record.namespace,
                "container_name": record.container_name,
                "manifest_path": record.manifest_path,
                "source_finding_type": K8sFindingType.MANIFEST.value,
                "unmapped": record.unmapped,
            },
        )
        out.append(finding)
    return tuple(out)


def _build_finding_id(*, sequence: int, slug_seed: str) -> str:
    """Construct an F.3-shaped finding_id: `CSPM-KUBERNETES-MANIFEST-NNN-<slug>`."""
    src = source_token(K8sFindingType.MANIFEST)
    context = _slugify(slug_seed)[:40] or "manifest"
    return f"CSPM-KUBERNETES-{src}-{sequence:03d}-{context}"


def _slugify(value: str) -> str:
    """Lowercase + replace runs of non-alphanumerics with hyphens; strip leading/trailing."""
    low = value.lower()
    slug = _SLUG_RE.sub("-", low).strip("-")
    return slug or ""


__all__ = ["normalize_manifest"]
