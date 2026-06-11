"""RBAC + runtime finding emission to OCSF 2003 (D.6 v0.2 Task 13).

Converts the v0.2 live-only findings — RBAC over-privilege (Task 12) and runtime posture
violations (Task 10) — into OCSF 2003 Compliance Findings via the shared `build_finding`,
mirroring the kube-bench/Polaris normalizers' F.3 wire shape. These are **new finding
types** (`RBAC` / `RUNTIME`) emitted only on the live path, so the offline `run()`/eval
output is unchanged (WI-K5 byte-identical).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from shared.fabric.envelope import NexusEnvelope

from k8s_posture.rbac.over_privileged import RbacFinding
from k8s_posture.runtime.posture_rules import RuntimeViolation
from k8s_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    K8sFindingType,
    Severity,
    build_finding,
    source_token,
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.lower()).strip("-")[:40] or "k8s"


def _finding_id(finding_type: K8sFindingType, *, sequence: int, slug_seed: str) -> str:
    return f"CSPM-KUBERNETES-{source_token(finding_type)}-{sequence:03d}-{_slug(slug_seed)}"


def emit_rbac_findings(
    findings: Sequence[RbacFinding], *, envelope: NexusEnvelope, scan_time: datetime
) -> tuple[CloudPostureFinding, ...]:
    """RBAC over-privilege findings → OCSF 2003."""
    out: list[CloudPostureFinding] = []
    for i, f in enumerate(findings, start=1):
        namespace = f.namespace or "cluster"
        resource_id = f"{namespace}/{f.kind}/{f.name}"
        out.append(
            build_finding(
                finding_id=_finding_id(
                    K8sFindingType.RBAC, sequence=i, slug_seed=f"{f.rule_id}-{f.name}"
                ),
                rule_id=f.rule_id,
                severity=Severity(f.severity),
                title=f"RBAC: {f.rule_id} ({f.name})",
                description=f.message,
                affected=[
                    AffectedResource(
                        cloud="kubernetes",
                        account_id=namespace,
                        region="cluster",
                        resource_type=f.kind,
                        resource_id=resource_id,
                        arn=f"k8s://rbac/{resource_id}",
                    )
                ],
                detected_at=scan_time,
                envelope=envelope,
                evidence={
                    "kind": "rbac",
                    "rule_id": f.rule_id,
                    "resource_kind": f.kind,
                    "name": f.name,
                    "namespace": f.namespace,
                    "message": f.message,
                    "source_finding_type": K8sFindingType.RBAC.value,
                },
            )
        )
    return tuple(out)


def emit_runtime_findings(
    violations: Sequence[RuntimeViolation], *, envelope: NexusEnvelope, scan_time: datetime
) -> tuple[CloudPostureFinding, ...]:
    """Runtime posture violations → OCSF 2003."""
    out: list[CloudPostureFinding] = []
    for i, v in enumerate(violations, start=1):
        resource_id = f"{v.namespace}/{v.pod}" + (f"/{v.container}" if v.container else "")
        out.append(
            build_finding(
                finding_id=_finding_id(
                    K8sFindingType.RUNTIME, sequence=i, slug_seed=f"{v.rule_id}-{v.pod}"
                ),
                rule_id=v.rule_id,
                severity=Severity(v.severity),
                title=f"Runtime: {v.rule_id} ({v.pod})",
                description=v.message,
                affected=[
                    AffectedResource(
                        cloud="kubernetes",
                        account_id=v.namespace,
                        region="cluster",
                        resource_type="Pod",
                        resource_id=resource_id,
                        arn=f"k8s://runtime/{resource_id}",
                    )
                ],
                detected_at=scan_time,
                envelope=envelope,
                evidence={
                    "kind": "runtime",
                    "rule_id": v.rule_id,
                    "namespace": v.namespace,
                    "pod": v.pod,
                    "container": v.container,
                    "message": v.message,
                    "source_finding_type": K8sFindingType.RUNTIME.value,
                },
            )
        )
    return tuple(out)
