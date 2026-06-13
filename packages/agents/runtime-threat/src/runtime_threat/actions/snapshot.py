"""Forensic snapshot action emission (D.3 v0.2 Task 13).

The **only** action D.3 emits at v0.2 is a **read-only forensic snapshot** request
(capture workload state for investigation). Per **Q4 / WI-R8** there is **no** process
kill and **no** workload quarantine at v0.2 — those Tier-1 actions are deferred to the
A.1 Remediation cycle (WI-R9). `assert_authorized` is the hard guard: any attempt to
emit a non-snapshot action raises (backstops pause-trigger #11).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime

from runtime_threat.schemas import RuntimeFinding, Severity

#: The only action type authorized at v0.2 — read-only (Q4/WI-R8).
AUTHORIZED_ACTION_TYPES = frozenset({"snapshot"})

#: Findings at these severities warrant a read-only forensic snapshot for investigation.
_SNAPSHOT_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


class UnauthorizedActionError(RuntimeError):
    """A non-snapshot (kill/quarantine) action was attempted — forbidden at v0.2."""


def assert_authorized(action_type: str) -> None:
    """Raise unless ``action_type`` is authorized at v0.2 (snapshot only). Kill /
    quarantine are deferred to the A.1 Remediation cycle (WI-R9)."""
    if action_type not in AUTHORIZED_ACTION_TYPES:
        raise UnauthorizedActionError(
            f"action {action_type!r} is not authorized at D.3 v0.2 — only 'snapshot' "
            f"(read-only); process kill / workload quarantine → A.1 Remediation cycle"
        )


@dataclass(frozen=True, slots=True)
class SnapshotAction:
    host_id: str
    container_id: str
    reason: str
    requested_at: str  # ISO 8601
    action_type: str = "snapshot"

    @property
    def is_read_only(self) -> bool:
        """Always True — a snapshot captures state; it never mutates the workload."""
        return True


def request_workload_snapshot(
    host_id: str,
    container_id: str,
    *,
    reason: str,
    requested_at: datetime,
) -> SnapshotAction:
    """Emit a read-only forensic snapshot action request for a workload. Requires at
    least one of ``host_id`` / ``container_id`` to target."""
    if not host_id and not container_id:
        raise ValueError("a snapshot needs a host_id or container_id to target")
    assert_authorized("snapshot")
    return SnapshotAction(
        host_id=host_id,
        container_id=container_id,
        reason=reason,
        requested_at=requested_at.isoformat(),
    )


def build_snapshot_actions(
    findings: Sequence[RuntimeFinding],
    *,
    requested_at: datetime,
) -> list[SnapshotAction]:
    """Emit a read-only forensic snapshot request per HIGH/CRITICAL finding (Phase C SS2).

    This is the run-flow integration point that makes ``assert_authorized`` load-bearing: every
    emitted action routes through ``request_workload_snapshot`` -> ``assert_authorized('snapshot')``,
    so a future kill/quarantine action could never be emitted from the run loop without tripping
    the guard. Findings below HIGH, or without a targetable host, are skipped.
    """
    actions: list[SnapshotAction] = []
    for finding in findings:
        if finding.severity not in _SNAPSHOT_SEVERITIES:
            continue
        host_ids = finding.host_ids
        host_id = host_ids[0] if host_ids else ""
        if not host_id:
            continue
        actions.append(
            request_workload_snapshot(
                host_id=host_id,
                container_id="",
                reason=f"{finding.title} ({finding.finding_id})",
                requested_at=requested_at,
            )
        )
    return actions


def snapshot_actions_to_json(actions: Sequence[SnapshotAction]) -> str:
    """Render snapshot actions as the additive ``snapshot_actions.json`` workspace artifact."""
    return json.dumps([asdict(a) for a in actions], indent=2)
