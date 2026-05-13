"""Network-threat finding schemas — OCSF v1.3 Detection Finding (class_uid 2004).

**Q1 resolution (per the D.4 plan).** Network-threat findings are
analyst-interpreted detections (port_scan / beacon / dga / suricata
alert) wrapping raw network-layer observations (VPC flow records, DNS
queries, Suricata ndjson). The right OCSF class is `2004 Detection
Finding` — same as D.2 Identity and D.3 Runtime Threat.

Two reasons (mirroring D.3's Q1):

1. OCSF `4001 Network Activity` is observation-shaped, not
   finding-shaped — it describes a raw flow record, not an analyst's
   verdict. Mixing detection findings with raw activity muddles
   downstream consumers (fabric, Meta-Harness) that dispatch on
   `class_uid`.
2. The detection-finding shape carries the analyst's interpretation
   (`finding_type`, `severity`, evidence dict, detector_id) wrapping
   the underlying flow record. The raw flow / dns / alert can ride
   inside `evidences[0]` as a typed sub-model.

Cross-agent OCSF inventory after D.4:

| Agent                 | OCSF class_uid | Class name             |
| --------------------- | -------------- | ---------------------- |
| Cloud Posture (F.3)   | 2003           | Compliance Finding     |
| Vulnerability (D.1)   | 2002           | Vulnerability Finding  |
| Identity (D.2)        | 2004           | Detection Finding      |
| Runtime Threat (D.3)  | 2004           | Detection Finding      |
| Audit (F.6)           | 6003           | API Activity           |
| Investigation (D.7)   | 2005           | Incident Finding       |
| **Network Threat (D.4)** | **2004**    | **Detection Finding**  |

D.2 + D.3 + D.4 sharing 2004 is *correct* — all three produce "an
analyst flagged this state/behavior as suspicious" records. The
`finding_info.types[0]` field carries each agent's domain-specific
`FindingType` enum so downstream filters can dispatch on
(class_uid 2004, finding_type) pairs.

**ADR-007 v1.2 pattern check (D.4 risk-down):** the
schema-as-typing-layer pattern carries over verbatim from D.3. Deltas:

1. New `FindingType` enum (four buckets: PORT_SCAN / BEACON / DGA /
   SURICATA) — domain-specific to network threats.
2. `AffectedNetwork` instead of `AffectedHost` — network findings
   describe (src_ip, dst_ip, src_cidr) pairs, not workload hosts.
3. **Three input observation models** (`FlowRecord`, `DnsEvent`,
   `SuricataAlert`) — D.3 had only the post-normalized envelope; D.4
   has three feed types with three distinct wire formats, so each
   carries its own typed model and the normalizer collapses them.
4. `Beacon` and `Detection` as intermediate dataclasses — Beacon
   carries periodicity stats (inter-arrival-time variance, count,
   period); Detection is the generic pre-finding shape.

Verdict: pattern generalizes; no ADR-007 amendment surfaced from D.4.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf

FINDING_ID_RE = re.compile(
    r"^NETWORK-(PORT_SCAN|BEACON|DGA|SURICATA)-[A-Z0-9]+-\d{3}-[a-z0-9_.-]+$"
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
    """Network-threat finding categories. Drives the second token in finding_id."""

    PORT_SCAN = "network_port_scan"
    BEACON = "network_beacon"
    DGA = "network_dga"
    SURICATA = "network_suricata"


_FT_TOKEN: dict[FindingType, str] = {
    FindingType.PORT_SCAN: "PORT_SCAN",
    FindingType.BEACON: "BEACON",
    FindingType.DGA: "DGA",
    FindingType.SURICATA: "SURICATA",
}


def finding_type_token(ft: FindingType) -> str:
    """Return the FINDING_ID_RE token (e.g. `PORT_SCAN`) for a `FindingType`."""
    return _FT_TOKEN[ft]


# ---------------------------- FlowRecord ---------------------------------


class FlowRecord(BaseModel):
    """Parsed AWS VPC Flow Logs v5 record (raw observation; NOT a finding).

    Fields cover the v3/v4/v5 superset. Trailing unknown fields are
    preserved under `unmapped` (mirrors the OCSF wire-format pattern).
    """

    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    bytes_transferred: int = Field(ge=0)
    packets: int = Field(ge=0)
    start_time: datetime
    end_time: datetime
    action: str = Field(pattern=r"^(ACCEPT|REJECT|NODATA|SKIPDATA)$")
    log_status: str = Field(default="OK")
    account_id: str = ""
    interface_id: str = ""
    vpc_id: str = ""
    unmapped: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


# ---------------------------- DnsEvent -----------------------------------


class DnsEventKind(StrEnum):
    QUERY = "query"
    RESPONSE = "response"


class DnsEvent(BaseModel):
    """Parsed DNS query/response event from BIND query log or Route 53 Resolver Query Logs.

    BIND `query` lines and Route 53 Resolver `query_type` records collapse
    to the same shape here. `query_name` is normalised to lowercase with
    trailing dot stripped.
    """

    timestamp: datetime
    kind: DnsEventKind
    query_name: str = Field(min_length=1)
    query_type: str = Field(default="A")
    src_ip: str = ""
    resolver_endpoint: str = ""
    rcode: str = Field(default="NOERROR")
    answers: tuple[str, ...] = Field(default_factory=tuple)
    unmapped: dict[str, Any] = Field(default_factory=dict)


# ---------------------------- SuricataAlert ------------------------------


class SuricataAlertSeverity(StrEnum):
    """Suricata severity mapping (1-3 from the Suricata signature classtype)."""

    HIGH = "1"
    MEDIUM = "2"
    LOW = "3"


class SuricataAlert(BaseModel):
    """Parsed Suricata eve.json alert event (raw observation; not a finding).

    Only the `alert` event_type is modeled here; `fileinfo` / `dns` /
    `http` / `flow` are parsed by their respective readers (DnsEvent
    for DNS events; the flow records flow through `FlowRecord` if the
    operator opts to feed Suricata flow output through that reader).
    """

    timestamp: datetime
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(min_length=1)
    signature_id: int = Field(ge=1)
    signature: str = Field(min_length=1)
    category: str = ""
    severity: SuricataAlertSeverity
    rev: int = Field(default=1, ge=1)
    unmapped: dict[str, Any] = Field(default_factory=dict)


# ---------------------------- Beacon -------------------------------------


class Beacon(BaseModel):
    """A detected beacon — repeated connection pattern from one src to one dst.

    `period_seconds` is the mean inter-arrival time across observed
    connections. `variance_seconds` is the variance — low variance +
    high count = high confidence. `confidence` is a derived score in
    [0, 1] computed by `detectors.beacon`.
    """

    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    dst_port: int = Field(ge=0, le=65535)
    connection_count: int = Field(ge=2)
    period_seconds: float = Field(ge=0.0)
    variance_seconds: float = Field(ge=0.0)
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime


# ---------------------------- Detection ----------------------------------


class Detection(BaseModel):
    """Intermediate detection result — the pre-finding shape.

    The three detectors (`port_scan`, `beacon`, `dga`) plus the
    `suricata` normalizer each emit `Detection` instances. The driver
    converts them into `NetworkFinding` records via `build_finding`.

    `evidence` is detector-specific:
    - PORT_SCAN: `{src_ip, distinct_ports, window_seconds, ports_sampled}`
    - BEACON:    `{src_ip, dst_ip, period_seconds, variance_seconds, count}`
    - DGA:       `{query_name, entropy, bigram_score, src_ip}`
    - SURICATA:  `{signature_id, signature, src_ip, dst_ip}`
    """

    finding_type: FindingType
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    detector_id: str = Field(min_length=1)
    src_ip: str = ""
    dst_ip: str = ""
    src_cidr: str = ""
    detected_at: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)

    def dedup_key(self) -> tuple[str, str, str, int]:
        """Composite dedup key (per Q6 of the plan): (detection_type, src_cidr_or_ip, dst_cidr_or_ip, 5min_bucket).

        Two detectors flagging the same beacon from the same src dedupe
        to one finding when the keys match.
        """
        bucket = int(self.detected_at.timestamp()) // 300
        return (
            self.finding_type.value,
            self.src_cidr or self.src_ip,
            self.dst_ip,
            bucket,
        )


# ---------------------------- AffectedNetwork ----------------------------


class AffectedNetwork(BaseModel):
    """The network endpoint(s) the finding describes.

    `src_ip` is required (the actor); `dst_ip` is optional (DGA findings
    are src-only — the lookup didn't reach an IP). `src_cidr` is an
    aggregation hint for dedup + summarisation.
    """

    src_ip: str = Field(min_length=1)
    dst_ip: str = ""
    src_cidr: str = ""
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    vpc_id: str = ""
    account_id: str = ""

    def to_ocsf(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ip": self.src_ip}
        if self.dst_ip:
            out["traffic"] = {"dst_ip": self.dst_ip}
        if self.src_cidr:
            out["subnet_uid"] = self.src_cidr
        if self.src_port:
            out["port"] = self.src_port
        if self.dst_port:
            out.setdefault("traffic", {})["dst_port"] = self.dst_port
        if self.vpc_id:
            out["vpc_uid"] = self.vpc_id
        if self.account_id:
            out["account_uid"] = self.account_id
        return out


# ---------------------------- NetworkFinding wrapper ---------------------


class NetworkFinding:
    """Typed wrapper over a wrapped OCSF v1.3 Detection Finding dict (network flavor)."""

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
    def affected_networks(self) -> list[dict[str, Any]]:
        return list(self._payload.get("affected_networks", []))

    @property
    def src_ips(self) -> list[str]:
        return [str(n.get("ip", "")) for n in self.affected_networks]

    @property
    def evidence(self) -> dict[str, Any]:
        evs = self._payload.get("evidences") or []
        if not evs:
            return {}
        first = evs[0]
        return dict(first) if isinstance(first, dict) else {}

    @property
    def detector_id(self) -> str:
        return str(self._payload["finding_info"].get("product_uid", ""))

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
    affected_networks: list[AffectedNetwork],
    evidence: dict[str, Any],
    detected_at: datetime,
    envelope: NexusEnvelope,
    detector_id: str,
) -> NetworkFinding:
    """Build a Nexus OCSF v1.3 Detection Finding (Network Threat flavor).

    `finding_id` must match `FINDING_ID_RE`
    (`NETWORK-<TYPE>-<SHORT_IP>-NNN-<context>`).
    `affected_networks` must be non-empty.
    `evidence` is finding-type-specific; preserved verbatim under OCSF
    `evidences[0]`. Common keys per type:

    - PORT_SCAN: `src_ip`, `distinct_ports`, `window_seconds`, `ports_sampled`.
    - BEACON:    `src_ip`, `dst_ip`, `period_seconds`, `variance_seconds`, `connection_count`.
    - DGA:       `query_name`, `entropy`, `bigram_score`, `src_ip`.
    - SURICATA:  `signature_id`, `signature`, `src_ip`, `dst_ip`.

    `detector_id` is the upstream detector's identifier (e.g.
    `port_scan@0.1.0`, `dga@0.1.0`, `suricata:2024-001`).
    """
    if not FINDING_ID_RE.match(finding_id):
        raise ValueError(f"finding_id must match {FINDING_ID_RE.pattern} (got {finding_id!r})")
    if not affected_networks:
        raise ValueError("affected_networks list must not be empty")

    timestamp_ms = int(detected_at.timestamp() * 1000)
    finding_info: dict[str, Any] = {
        "uid": finding_id,
        "title": title,
        "desc": description,
        "first_seen_time": timestamp_ms,
        "last_seen_time": timestamp_ms,
        "types": [finding_type.value],
        "product_uid": detector_id,
    }

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
                "name": "Nexus Network Threat",
                "vendor_name": "Nexus Cyber OS",
            },
        },
        "finding_info": finding_info,
        "affected_networks": [n.to_ocsf() for n in affected_networks],
        "evidences": [dict(evidence)] if evidence else [],
    }
    wrapped = wrap_ocsf(payload, envelope)
    return NetworkFinding(wrapped)


# ---------------------------- FindingsReport -----------------------------


class FindingsReport(BaseModel):
    """Aggregate report metadata produced by a Network Threat Agent invocation."""

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

    def add_finding(self, f: NetworkFinding) -> None:
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


def short_ip_token(ip: str) -> str:
    """Extract a finding-id-safe token from an IP address.

    Dotted IPv4 (`10.0.1.42`) collapses to `10_0_1_42` then uppercases
    to `100142`-shape via dot removal. We keep dashes/dots out by
    converting non-alphanumerics to nothing.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", ip).upper()
    if not safe:
        return "UNKNOWN"
    return safe[:12]


__all__ = [
    "FINDING_ID_RE",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "AffectedNetwork",
    "Beacon",
    "Detection",
    "DnsEvent",
    "DnsEventKind",
    "FindingType",
    "FindingsReport",
    "FlowRecord",
    "NetworkFinding",
    "Severity",
    "SuricataAlert",
    "SuricataAlertSeverity",
    "build_finding",
    "finding_type_token",
    "severity_from_id",
    "severity_to_id",
    "short_ip_token",
]
