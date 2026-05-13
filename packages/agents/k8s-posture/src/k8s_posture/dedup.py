"""`dedupe_overlapping` — composite-key collapse stage for K8s posture findings.

Pure-function dedup over the merged stream of normalised
`CloudPostureFinding`s (kube-bench + Polaris + manifest). Two findings
collapse when they share `(rule_id, namespace, workload_arn,
time_bucket)`. Operators receive a single OCSF record per posture
issue, with collapsed siblings' IDs preserved in a `dedup-sources`
evidence entry on the survivor.

**Composite key**
- `rule_id`: OCSF `compliance.control` (kube-bench control_id / Polaris
  check_id / manifest rule_id).
- `namespace`: first AffectedResource's `account_uid` (kube-bench
  uses `node_type` here — fine, it's a cluster-scope discriminator).
- `workload_arn`: first AffectedResource's `uid` (full arn).
  Container fragments (`#nginx`) are preserved so distinct containers
  on the same workload stay distinct.
- `time_bucket`: `int(detected_at_ms // window_ms)` — defaults to a
  5-minute bucket (per Q3 of the D.6 plan).

**Survivor selection** — when two findings collide:
1. Higher OCSF severity_id wins (CRITICAL=5 > HIGH=4 > … > INFO=1).
2. Ties broken by input order (first-seen wins).

The survivor's payload is preserved verbatim and gains one extra
evidence entry of the form
`{"kind": "dedup-sources", "finding_ids": [<loser_ids…>]}`.

**Boundaries** — kube-bench and Polaris/manifest never collide in
practice because they scan different domains (cluster controls vs
workloads → different rule_ids + different arn schemes). Manifest
analyser's `run-as-root` and Polaris's `runAsRootAllowed` likewise
keep distinct rule_ids; an ontology map could merge them in a future
revision but v0.1 deliberately keeps the simpler rule-id-exact policy.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from cloud_posture.schemas import CloudPostureFinding

DEFAULT_WINDOW = timedelta(minutes=5)


def dedupe_overlapping(
    findings: Sequence[CloudPostureFinding],
    *,
    window: timedelta = DEFAULT_WINDOW,
) -> tuple[CloudPostureFinding, ...]:
    """Collapse overlapping findings on `(rule_id, namespace, workload, time_bucket)`.

    See module docstring for the full key + survivor rules. Input order
    is preserved for the survivors so downstream rendering is stable.
    """
    if not findings:
        return ()

    window_ms = max(1, int(window.total_seconds() * 1000))
    survivors: dict[tuple[str, str, str, int], _Bucket] = {}
    order: list[tuple[str, str, str, int]] = []

    for finding in findings:
        payload = finding.to_dict()
        rule_id = str(payload.get("compliance", {}).get("control", ""))
        resources = payload.get("resources") or [{}]
        first_resource = resources[0] if isinstance(resources[0], dict) else {}
        namespace = str(first_resource.get("owner", {}).get("account_uid", ""))
        workload_arn = str(first_resource.get("uid", ""))
        time_ms = int(payload.get("time", 0))
        bucket_idx = time_ms // window_ms
        key = (rule_id, namespace, workload_arn, bucket_idx)
        severity_id = int(payload.get("severity_id", 0))

        existing = survivors.get(key)
        if existing is None:
            survivors[key] = _Bucket(finding=finding, severity_id=severity_id, collapsed=[])
            order.append(key)
            continue

        # Collision — pick the winner.
        if severity_id > existing.severity_id:
            existing.collapsed.append(existing.finding.finding_id)
            existing.finding = finding
            existing.severity_id = severity_id
        else:
            existing.collapsed.append(finding.finding_id)

    out: list[CloudPostureFinding] = []
    for key in order:
        bucket = survivors[key]
        if not bucket.collapsed:
            out.append(bucket.finding)
        else:
            out.append(_attach_dedup_sources(bucket.finding, bucket.collapsed))
    return tuple(out)


# ---------------------------- helpers -------------------------------------


class _Bucket:
    """Mutable survivor cell — current finding + severity + collapsed loser IDs."""

    __slots__ = ("collapsed", "finding", "severity_id")

    def __init__(
        self,
        *,
        finding: CloudPostureFinding,
        severity_id: int,
        collapsed: list[str],
    ) -> None:
        self.finding = finding
        self.severity_id = severity_id
        self.collapsed = collapsed


def _attach_dedup_sources(
    finding: CloudPostureFinding,
    collapsed_ids: list[str],
) -> CloudPostureFinding:
    """Return a new CloudPostureFinding with a `dedup-sources` evidence appended."""
    payload: dict[str, Any] = copy.deepcopy(finding.to_dict())
    evidences = payload.setdefault("evidences", [])
    evidences.append(
        {
            "kind": "dedup-sources",
            "finding_ids": list(collapsed_ids),
        }
    )
    return CloudPostureFinding(payload)


__all__ = ["DEFAULT_WINDOW", "dedupe_overlapping"]
