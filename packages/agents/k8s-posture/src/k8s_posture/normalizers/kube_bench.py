"""`normalize_kube_bench` — kube-bench raw findings → OCSF 2003 Compliance Findings.

Pure-function normalizer (no I/O, no async). Takes the typed reader
output from `tools/kube_bench.py` and produces a tuple of
`CloudPostureFinding` (re-exported from F.3 via `schemas.py`).

**Severity mapping** (per Q5):

| Source value                               | OCSF `Severity` |
| ------------------------------------------ | --------------- |
| `FAIL`                                     | HIGH            |
| `WARN`                                     | MEDIUM          |
| (any status + `severity: critical` marker) | CRITICAL        |

**Finding-id construction:** `CSPM-KUBERNETES-CIS-{seq:03d}-{slug}`
where `slug` carries the dotted CIS control ID with dots normalised to
hyphens (e.g. `1-1-1-master-pod-spec-permissions`). Per-(node_type,
node_type) sequence counter so finding IDs are stable within a run.

**Resource shape** — kube-bench findings describe a control on a node,
not a workload. The OCSF `AffectedResource` carries:

- `cloud = "kubernetes"`
- `account_id = <node_type or "cluster">` (master / worker / etcd / controlplane)
- `region = "cluster"`
- `resource_type = "Node"` (or whatever `node_type` suggests, capitalised)
- `resource_id = "<node_type>/<control_id>"`
- `arn = "k8s://cis/<node_type>/<control_id>"`
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
    kube_bench_severity,
    source_token,
)
from k8s_posture.tools.kube_bench import KubeBenchFinding

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_kube_bench(
    findings: Sequence[KubeBenchFinding],
    *,
    envelope: NexusEnvelope,
    scan_time: datetime,
) -> tuple[CloudPostureFinding, ...]:
    """Convert kube-bench reader outputs into OCSF 2003 Compliance Findings."""
    out: list[CloudPostureFinding] = []
    seq_by_node: dict[str, int] = {}

    for record in findings:
        severity = kube_bench_severity(record.status, severity_marker=record.severity_marker)
        if severity is None:
            continue

        node_key = record.node_type or "cluster"
        seq_by_node[node_key] = seq_by_node.get(node_key, 0) + 1
        sequence = seq_by_node[node_key]

        slug_seed = f"{record.node_type}-{record.control_id}-{record.control_text}"
        finding_id = _build_finding_id(sequence=sequence, slug_seed=slug_seed)
        rule_id = record.control_id or "cis"
        resource_type = _resource_type_for_node(record.node_type)
        resource_id = f"{node_key}/{record.control_id}"
        arn = f"k8s://cis/{node_key}/{record.control_id}"

        affected = [
            AffectedResource(
                cloud="kubernetes",
                account_id=node_key,
                region="cluster",
                resource_type=resource_type,
                resource_id=resource_id,
                arn=arn,
            )
        ]
        finding = build_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            title=f"{record.control_id}: {record.control_text}",
            description=record.control_text,
            affected=affected,
            detected_at=record.detected_at or scan_time,
            envelope=envelope,
            evidence={
                "kind": "kube-bench",
                "control_id": record.control_id,
                "section_id": record.section_id,
                "section_desc": record.section_desc,
                "node_type": record.node_type,
                "status": record.status,
                "severity_marker": record.severity_marker,
                "audit": record.audit,
                "actual_value": record.actual_value,
                "remediation": record.remediation,
                "scored": record.scored,
                "source_finding_type": K8sFindingType.CIS.value,
                "unmapped": record.unmapped,
            },
        )
        out.append(finding)
    return tuple(out)


# ---------------------------- helpers -------------------------------------


def _build_finding_id(*, sequence: int, slug_seed: str) -> str:
    """Construct an F.3-shaped finding_id: `CSPM-KUBERNETES-CIS-NNN-<slug>`."""
    src = source_token(K8sFindingType.CIS)
    context = _slugify(slug_seed)[:40] or "cis"
    return f"CSPM-KUBERNETES-{src}-{sequence:03d}-{context}"


def _slugify(value: str) -> str:
    """Lowercase + replace runs of non-alphanumerics with hyphens; strip leading/trailing."""
    low = value.lower()
    slug = _SLUG_RE.sub("-", low).strip("-")
    return slug or ""


def _resource_type_for_node(node_type: str) -> str:
    """Map kube-bench `node_type` to a more presentable resource type label."""
    n = node_type.lower()
    if n == "master":
        return "MasterNode"
    if n == "worker":
        return "WorkerNode"
    if n == "etcd":
        return "EtcdNode"
    if n == "controlplane":
        return "ControlPlaneNode"
    if n == "policies":
        return "PolicyConfig"
    return "K8sNode"


__all__ = ["normalize_kube_bench"]
