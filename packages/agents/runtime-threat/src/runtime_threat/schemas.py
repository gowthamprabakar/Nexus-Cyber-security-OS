"""Runtime threat finding schemas — OCSF v1.3 Detection Finding (class_uid 2004).

**Q1 resolution (per the D.3 plan).** Runtime threat findings are detections
of suspicious behavior on a workload host, surfaced by eBPF sensors
(Falco / Tracee) or on-host query engines (OSQuery). The right OCSF class
is `class_uid 2004` Detection Finding — same as D.2 Identity. Two reasons:

1. The OCSF activity classes under category 1 (System Activity) describe
   raw OS telemetry events, not analyst-interpreted findings. Mixing
   detection findings with raw activity would muddle downstream
   consumers (fabric, Meta-Harness) that dispatch on `class_uid`.
2. The detection-finding shape carries an analyst's interpretation
   (rule_id, severity, evidence dict) that wraps the underlying
   activity record. The activity record itself can be embedded as
   evidence (e.g., `evidences[0].process` for a Process Activity dict).

Cross-agent OCSF inventory after D.3:

| Agent                | OCSF class_uid | Class name             |
| -------------------- | -------------- | ---------------------- |
| Cloud Posture (F.3)  | 2003           | Compliance Finding     |
| Vulnerability (D.1)  | 2002           | Vulnerability Finding  |
| Identity (D.2)       | 2004           | Detection Finding      |
| Runtime Threat (D.3) | 2004           | Detection Finding      |

D.2 and D.3 sharing 2004 is *correct* — both produce "an analyst flagged
this state/behavior as suspicious" records. The `finding_info.types[0]`
field carries each agent's domain-specific `FindingType` enum so
downstream filters can dispatch on (class_uid 2004, finding_type) pairs.

**ADR-007 v1.2 pattern check (D.3 risk-down):** the schema-as-typing-layer
pattern carries over verbatim from D.2. Deltas vs. D.2:

1. New `FindingType` enum (five buckets: PROCESS / FILE / NETWORK /
   SYSCALL / OSQUERY) — domain-specific to runtime threats.
2. `AffectedHost` instead of `AffectedPrincipal` — runtime findings live
   on workload hosts (containers, pods, VMs), not IAM principals.
3. `evidence` dict carries finding-type-specific context (e.g.,
   `process.cmdline`, `file.path`, `network.remote_ip`, `osquery.row`).

Verdict: pattern generalizes; no ADR-007 amendment surfaced from D.3.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

FINDING_ID_RE = re.compile(
    r"^RUNTIME-(PROCESS|FILE|NETWORK|SYSCALL|OSQUERY)-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$"
)

# OCSF v1.3 constants
OCSF_VERSION = "1.3.0"
OCSF_CATEGORY_UID = 2  # Findings
OCSF_CATEGORY_NAME = "Findings"
OCSF_CLASS_UID = 2004  # Detection Finding
OCSF_CLASS_NAME = "Detection Finding"
OCSF_ACTIVITY_CREATE = 1
OCSF_STATUS_NEW = 1


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_TO_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_ID_TO_SEVERITY: dict[int, Severity] = {
    **{v: k for k, v in _SEVERITY_TO_ID.items()},
    6: Severity.CRITICAL,  # OCSF Fatal collapses to critical
}


def severity_to_id(s: Severity) -> int:
    return _SEVERITY_TO_ID[s]


def severity_from_id(i: int) -> Severity:
    if i not in _ID_TO_SEVERITY:
        raise ValueError(f"unknown OCSF severity_id: {i}")
    return _ID_TO_SEVERITY[i]


class FindingType(StrEnum):
    """Runtime-threat finding categories. Drives the second token in finding_id."""

    PROCESS = "runtime_process"
    FILE = "runtime_file"
    NETWORK = "runtime_network"
    SYSCALL = "runtime_syscall"
    OSQUERY = "runtime_osquery"


# Map FindingType to the short token used inside finding_id (matches FINDING_ID_RE).
_FT_TOKEN: dict[FindingType, str] = {
    FindingType.PROCESS: "PROCESS",
    FindingType.FILE: "FILE",
    FindingType.NETWORK: "NETWORK",
    FindingType.SYSCALL: "SYSCALL",
    FindingType.OSQUERY: "OSQUERY",
}


def finding_type_token(ft: FindingType) -> str:
    """Return the FINDING_ID_RE token (e.g. `PROCESS`) for a `FindingType`."""
    return _FT_TOKEN[ft]


# ---------------------------- AffectedHost -------------------------------


class AffectedHost(BaseModel):
    """One workload host (container / pod / VM / bare metal) the finding describes.

    `host_id` is the most-specific identifier available — typically a
    container ID or k8s pod UID. `image_ref` is the OCI image reference
    for the running workload (empty for bare-metal hosts). `ip_addresses`
    is the host's IPs as observed at detection time.
    """

    hostname: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    image_ref: str = ""
    namespace: str = ""
    node_id: str = ""
    ip_addresses: tuple[str, ...] = Field(default_factory=tuple)

    def to_ocsf(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "hostname": self.hostname,
            "uid": self.host_id,
        }
        if self.image_ref:
            out["image"] = {"ref": self.image_ref}
        if self.namespace:
            out["namespace"] = self.namespace
        if self.node_id:
            out["node_uid"] = self.node_id
        if self.ip_addresses:
            out["ip"] = list(self.ip_addresses)
        return out


# ---------------------------- RuntimeFinding wrapper ---------------------


class RuntimeFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Detection Finding dict (runtime flavor)."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("class_uid") != OCSF_CLASS_UID:
            raise ValueError(
                f"expected OCSF class_uid={OCSF_CLASS_UID}, got {payload.get('class_uid')!r}"
            )
        finding_id = payload.get("finding_info", {}).get("uid", "")
        if not FINDING_ID_RE.match(finding_id):
            raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
        unwrap_ocsf(payload)  # raises if envelope missing/malformed
        self._payload = payload

    @property
    def severity(self) -> Severity:
        return severity_from_id(int(self._payload["severity_id"]))

    @property
    def finding_id(self) -> str:
        return str(self._payload["finding_info"]["uid"])

    @property
    def title(self) -> str:
        return str(self._payload["finding_info"]["title"])

    @property
    def description(self) -> str:
        return str(self._payload["finding_info"]["desc"])

    @property
    def envelope(self) -> NexusEnvelope:
        _, env = unwrap_ocsf(self._payload)
        return env

    @property
    def finding_type(self) -> FindingType:
        return FindingType(str(self._payload["finding_info"]["types"][0]))

    @property
    def affected_hosts(self) -> list[dict[str, Any]]:
        return list(self._payload.get("affected_hosts", []))

    @property
    def host_ids(self) -> list[str]:
        return [str(h.get("uid", "")) for h in self.affected_hosts]

    @property
    def evidence(self) -> dict[str, Any]:
        evs = self._payload.get("evidences") or []
        if not evs:
            return {}
        first = evs[0]
        return dict(first) if isinstance(first, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


# ---------------------------- build_finding ------------------------------


def build_finding(
    *,
    finding_id: str,
    finding_type: FindingType,
    severity: Severity,
    title: str,
    description: str,
    affected_hosts: list[AffectedHost],
    evidence: dict[str, Any],
    detected_at: datetime,
    envelope: NexusEnvelope,
    rule_id: str | None = None,
) -> RuntimeFinding:
    """Build a Nexus OCSF v1.3 Detection Finding (Runtime Threat flavor).

    `finding_id` must match `FINDING_ID_RE`
    (`RUNTIME-<TYPE>-<HOST_SHORT>-NNN-<context>`).
    `affected_hosts` must be non-empty.
    `evidence` is finding-type-specific; preserved verbatim under OCSF
    `evidences[0]`. Common keys per type:

    - PROCESS: `proc_cmdline`, `proc_pid`, `proc_user`, `parent_pid`.
    - FILE: `file_path`, `access_type` (read/write/exec).
    - NETWORK: `remote_ip`, `remote_port`, `direction`.
    - SYSCALL: `syscall_name`, `args`.
    - OSQUERY: `osquery_query`, `osquery_row`.

    `rule_id` is the upstream sensor's rule identifier (e.g. Falco rule
    name, Tracee event name). It lands in `finding_info.product_uid`.
    """
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not affected_hosts:
        raise ValueError("affected_hosts list must not be empty")

    timestamp_ms = int(detected_at.timestamp() * 1000)
    finding_info: dict[str, Any] = {
        "uid": finding_id,
        "title": title,
        "desc": description,
        "first_seen_time": timestamp_ms,
        "last_seen_time": timestamp_ms,
        "types": [finding_type.value],
    }
    if rule_id:
        finding_info["product_uid"] = rule_id

    payload: dict[str, Any] = {
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_CREATE,
        "type_name": f"{OCSF_CLASS_NAME}: Create",
        "severity_id": severity_to_id(severity),
        "severity": severity.value.capitalize(),
        "time": timestamp_ms,
        "time_dt": detected_at.isoformat(),
        "status_id": OCSF_STATUS_NEW,
        "status": "New",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Nexus Runtime Threat",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": finding_info,
        "affected_hosts": [h.to_ocsf() for h in affected_hosts],
        "evidences": [dict(evidence)] if evidence else [],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return RuntimeFinding(wrapped)


# ---------------------------- FindingsReport -----------------------------


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by a Runtime Threat Agent invocation."""

    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    scan_started_at: datetime
    scan_completed_at: datetime
    findings: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    def add_finding(self, f: RuntimeFinding) -> None:
        self.findings.append(f.to_dict())

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for raw in self.findings:
            sid = raw.get("severity_id")
            if sid is None:
                continue
            counts[severity_from_id(int(sid)).value] += 1
        return counts

    def count_by_finding_type(self) -> dict[str, int]:
        counts = dict.fromkeys((ft.value for ft in FindingType), 0)
        for raw in self.findings:
            types = raw.get("finding_info", {}).get("types") or []
            if types:
                ft_value = str(types[0])
                if ft_value in counts:
                    counts[ft_value] += 1
        return counts


# ---------------------------- helper for finding-id construction ---------


def short_host_id(host_id: str) -> str:
    """Extract a finding-id-safe identifier from a host identifier.

    Container IDs are long hex strings — take the first 12 chars (Docker convention).
    Kubernetes pod UIDs are dashed UUIDs — strip dashes and take the first 12.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", host_id).upper()
    if not safe:
        return "UNKNOWN"
    return safe[:12]


__all__ = [
    "FINDING_ID_RE",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "AffectedHost",
    "FindingType",
    "FindingsReport",
    "RuntimeFinding",
    "Severity",
    "build_finding",
    "finding_type_token",
    "severity_from_id",
    "severity_to_id",
    "short_host_id",
]
