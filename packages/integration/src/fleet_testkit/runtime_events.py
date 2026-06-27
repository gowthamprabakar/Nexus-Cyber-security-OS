"""In-memory runtime-threat harness — cross-domain path A2 (runtime feeder).

Runtime detections come from eBPF sensors (Falco/Tracee) and OSQuery; ``RuntimeFinding`` is the
agent's native finding type. ``drive_runtime_findings`` builds real findings (one suspicious
PROCESS event per workload) and runs runtime-threat's REAL ``record_findings`` writer, so the
runtime host node (carrying its ``image_ref``) lands in the graph for the image-ref bridge resolver
+ the runtime-exploit detector. The vulnerable image's CVEs come from real trivy (``vuln_scan``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from runtime_threat.kg_writer import KnowledgeGraphWriter as RuntimeKgWriter
from runtime_threat.schemas import (
    AffectedHost,
    FindingType,
    Severity,
    build_finding,
)
from shared.fabric.envelope import NexusEnvelope

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _envelope(tenant_id: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_test",
        tenant_id=tenant_id,
        agent_id="runtime_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="inv_test",
    )


async def drive_runtime_findings(
    store: SemanticStore, *, tenant_id: str, workloads: tuple[tuple[str, str], ...]
) -> None:
    """Run runtime-threat's REAL ``record_findings`` — one suspicious PROCESS event per workload.

    ``workloads`` is a tuple of ``(host_id, image_ref)``; each becomes a real ``RuntimeFinding``
    whose host node carries the ``image_ref`` (the join key for the runtime→vuln image bridge).
    """
    env = _envelope(tenant_id)
    findings = [
        build_finding(
            finding_id=f"RUNTIME-PROCESS-HOST{i:03d}-{i:03d}-evt",
            finding_type=FindingType.PROCESS,
            severity=Severity.HIGH,
            title="suspicious process exec",
            description="a suspicious process was observed on the workload",
            affected_hosts=[AffectedHost(hostname=f"h{i}", host_id=host_id, image_ref=image_ref)],
            evidence={"proc_cmdline": "/bin/sh -c curl evil", "proc_pid": 1234},
            detected_at=_NOW,
            envelope=env,
        )
        for i, (host_id, image_ref) in enumerate(workloads)
    ]
    await RuntimeKgWriter(store, tenant_id).record_findings(findings)


__all__ = ["drive_runtime_findings"]
