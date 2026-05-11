"""Findings normalizer — Runtime Threat Agent Task 7.

Maps the raw multi-feed inventory (`FalcoAlert[]`, `TraceeAlert[]`,
`OsqueryResult.rows[]`) into OCSF Detection Findings (`class_uid 2004`).
Five detection families, dispatched per sensor:

- **Falco alerts** → `FindingType` chosen from the alert's `tags`:
    - tag `process`, `shell`, `spawned`        → `RUNTIME_PROCESS`
    - tag `filesystem`, `file`                  → `RUNTIME_FILE`
    - tag `network`, `connection`               → `RUNTIME_NETWORK`
    - tag `syscall`, `kernel`                   → `RUNTIME_SYSCALL`
    - default                                   → `RUNTIME_PROCESS`
- **Tracee alerts** → `FindingType` from `event_name` prefix:
    - `security_file_*`                         → `RUNTIME_FILE`
    - `security_socket_*` / `net_*`             → `RUNTIME_NETWORK`
    - default                                   → `RUNTIME_SYSCALL`
- **OSQuery rows** → always `RUNTIME_OSQUERY`. One finding per row.

**No multi-feed dedup in v0.1.** If Falco AND Tracee both flag the same
incident (e.g. an `/etc/shadow` read), the normalizer emits two
findings. Downstream consumers (Investigation Agent, D.7) own the
cross-feed correlation. Deferred from D.3 to D.7 per the plan.

The function is async to mirror D.1/D.2's normalizer shape (ADR-007
v1.0 canon). All inputs are pre-loaded so the body is sync in v0.1;
the `async` keyword is the seam where future on-demand enrichment
(e.g., live MITRE ATT&CK technique lookup) will plug in.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from runtime_threat.schemas import (
    AffectedHost,
    FindingType,
    RuntimeFinding,
    build_finding,
    finding_type_token,
    short_host_id,
)
from runtime_threat.severity import (
    falco_to_severity,
    osquery_to_severity,
    tracee_to_severity,
)
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.osquery import OsqueryResult
from runtime_threat.tools.tracee import TraceeAlert

_CONTEXT_INVALID = re.compile(r"[^a-z0-9_-]")

# Falco tags that map a finding into a specific family. The first match
# wins (looped in declaration order) so the disambiguation rules are
# explicit: process tags beat file tags beat network tags etc.
_FALCO_TAG_TO_FINDING_TYPE: list[tuple[frozenset[str], FindingType]] = [
    (frozenset({"network", "connection"}), FindingType.NETWORK),
    (frozenset({"filesystem", "file"}), FindingType.FILE),
    (frozenset({"syscall", "kernel"}), FindingType.SYSCALL),
    (frozenset({"process", "shell", "spawned"}), FindingType.PROCESS),
]


async def normalize_to_findings(
    falco_alerts: Sequence[FalcoAlert],
    tracee_alerts: Sequence[TraceeAlert],
    osquery_results: Sequence[OsqueryResult],
    *,
    envelope: NexusEnvelope,
    detected_at: datetime | None = None,
    osquery_severity: int = 2,
    osquery_finding_context: str = "query_hit",
) -> list[RuntimeFinding]:
    """Produce OCSF Detection Findings from the multi-feed inventory.

    Args:
        falco_alerts: Output of `falco_alerts_read`.
        tracee_alerts: Output of `tracee_alerts_read`.
        osquery_results: Output of `osquery_run` (zero or more results;
            each may contain zero or more rows).
        envelope: NexusEnvelope to wrap every emitted finding with.
        detected_at: Timestamp on every finding (defaults to now).
        osquery_severity: OSQuery has no native severity; caller picks the
            scale (0-3, same as Tracee). Default 2 (medium).
        osquery_finding_context: Slug used in OSQuery findings' `context`
            field of the finding_id. Default `query_hit`.

    Returns:
        Findings in deterministic order: Falco, then Tracee, then OSQuery.
    """
    when = detected_at or datetime.now(UTC)

    findings: list[RuntimeFinding] = []
    findings.extend(_falco_findings(falco_alerts, envelope, when))
    findings.extend(_tracee_findings(tracee_alerts, envelope, when))
    findings.extend(
        _osquery_findings(
            osquery_results,
            envelope,
            when,
            severity_value=osquery_severity,
            context_slug=osquery_finding_context,
        )
    )
    return findings


# ---------------------------- per-tool helpers ---------------------------


def _falco_findings(
    alerts: Sequence[FalcoAlert],
    envelope: NexusEnvelope,
    when: datetime,
) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []
    counters: dict[FindingType, int] = {}

    for alert in alerts:
        finding_type = _falco_finding_type(alert.tags)
        counters[finding_type] = counters.get(finding_type, 0) + 1
        n = counters[finding_type]

        host = _falco_host(alert)
        context = _safe_context(alert.rule)
        severity = falco_to_severity(alert.priority)

        finding_id = (
            f"RUNTIME-{finding_type_token(finding_type)}-{short_host_id(host.host_id)}-"
            f"{n:03d}-{context}"
        )

        findings.append(
            build_finding(
                finding_id=finding_id,
                finding_type=finding_type,
                severity=severity,
                title=alert.rule,
                description=alert.output or alert.rule,
                affected_hosts=[host],
                evidence={
                    "falco_rule": alert.rule,
                    "falco_priority": alert.priority,
                    "falco_tags": list(alert.tags),
                    "output_fields": alert.output_fields,
                },
                detected_at=when,
                envelope=envelope,
                rule_id=alert.rule,
            )
        )
    return findings


def _tracee_findings(
    alerts: Sequence[TraceeAlert],
    envelope: NexusEnvelope,
    when: datetime,
) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []
    counters: dict[FindingType, int] = {}

    for alert in alerts:
        finding_type = _tracee_finding_type(alert.event_name)
        counters[finding_type] = counters.get(finding_type, 0) + 1
        n = counters[finding_type]

        host = _tracee_host(alert)
        context = _safe_context(alert.event_name)
        severity = tracee_to_severity(alert.severity)

        finding_id = (
            f"RUNTIME-{finding_type_token(finding_type)}-{short_host_id(host.host_id)}-"
            f"{n:03d}-{context}"
        )

        findings.append(
            build_finding(
                finding_id=finding_id,
                finding_type=finding_type,
                severity=severity,
                title=alert.description or alert.event_name,
                description=alert.description or alert.event_name,
                affected_hosts=[host],
                evidence={
                    "tracee_event": alert.event_name,
                    "tracee_severity": alert.severity,
                    "process_name": alert.process_name,
                    "process_id": alert.process_id,
                    "args": alert.args,
                },
                detected_at=when,
                envelope=envelope,
                rule_id=alert.event_name,
            )
        )
    return findings


def _osquery_findings(
    results: Sequence[OsqueryResult],
    envelope: NexusEnvelope,
    when: datetime,
    *,
    severity_value: int,
    context_slug: str,
) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []
    counter = 0
    severity = osquery_to_severity(severity_value)
    context = _safe_context(context_slug)

    for result in results:
        for row in result.rows:
            counter += 1
            host = _osquery_host(row)
            finding_id = f"RUNTIME-OSQUERY-{short_host_id(host.host_id)}-{counter:03d}-{context}"
            findings.append(
                build_finding(
                    finding_id=finding_id,
                    finding_type=FindingType.OSQUERY,
                    severity=severity,
                    title=f"OSQuery hit: {context_slug}",
                    description=f"OSQuery row from `{result.sql}` matched.",
                    affected_hosts=[host],
                    evidence={
                        "osquery_sql": result.sql,
                        "osquery_row": row,
                    },
                    detected_at=when,
                    envelope=envelope,
                    rule_id=context_slug,
                )
            )
    return findings


# ---------------------------- finding-type dispatch ---------------------


def _falco_finding_type(tags: tuple[str, ...]) -> FindingType:
    tag_set = frozenset(tags)
    for matchers, ft in _FALCO_TAG_TO_FINDING_TYPE:
        if matchers & tag_set:
            return ft
    return FindingType.PROCESS


def _tracee_finding_type(event_name: str) -> FindingType:
    if event_name.startswith("security_file_") or event_name.startswith("file_"):
        return FindingType.FILE
    if event_name.startswith("security_socket_") or event_name.startswith("net_"):
        return FindingType.NETWORK
    return FindingType.SYSCALL


# ---------------------------- host extraction ---------------------------


def _falco_host(alert: FalcoAlert) -> AffectedHost:
    fields = alert.output_fields
    container_id = str(fields.get("container.id", ""))
    image = str(fields.get("container.image.repository", ""))
    pod = str(fields.get("k8s.pod.name", ""))
    ns = str(fields.get("k8s.ns.name", ""))
    hostname = str(fields.get("container.name") or pod or "unknown-host")
    host_id = container_id or pod or hostname
    return AffectedHost(
        hostname=hostname or "unknown-host",
        host_id=host_id or "unknown-host",
        image_ref=image,
        namespace=ns,
    )


def _tracee_host(alert: TraceeAlert) -> AffectedHost:
    host_id = alert.container_id or alert.pod_name or alert.host_name or "unknown-host"
    hostname = alert.host_name or alert.pod_name or "unknown-host"
    return AffectedHost(
        hostname=hostname,
        host_id=host_id,
        image_ref=alert.container_image,
        namespace=alert.namespace,
    )


def _osquery_host(row: dict[str, str]) -> AffectedHost:
    """Best-effort host extraction from an OSQuery row.

    Conventional column names: `hostname`, `host_id`, `node_id`. Falls
    back to a literal "osquery-host" when none are present.
    """
    hostname = row.get("hostname") or row.get("host") or "osquery-host"
    host_id = row.get("host_id") or row.get("node_id") or hostname
    return AffectedHost(hostname=hostname, host_id=host_id)


# ---------------------------- low-level helpers --------------------------


def _safe_context(value: str) -> str:
    """Slug a free-form value into the `[a-z0-9_-]+` shape FINDING_ID_RE wants."""
    cleaned = _CONTEXT_INVALID.sub("-", value.lower())
    cleaned = cleaned.strip("-_") or "x"
    return cleaned


def _truthy(value: Any) -> bool:
    return bool(value)


__all__ = ["normalize_to_findings"]
