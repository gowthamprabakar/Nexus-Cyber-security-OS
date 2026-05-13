"""`detect_beacon` — periodicity-analysis heuristic over FlowRecord input.

Pure-function detector (no I/O, no async). Groups flow records by
`(src_ip, dst_ip, dst_port)` and inspects each group for periodic
connection patterns — the signature of C2 beaconing, scheduled
exfil, or other automation reaching out at regular intervals.

**Statistics computed per group** (the canonical beacon test):
- `count` — number of connections in the window
- `period_seconds` — mean inter-arrival time
- `variance_seconds` — variance of inter-arrival times
- `coefficient_of_variation` (CoV) = stddev / mean — low CoV =
  high periodicity = high beacon likelihood

**Defaults** (per Q3 of the plan; in-memory single-window):
- `min_count = 5` — below this the variance statistic isn't
  meaningful (one outlier dominates).
- `max_cov = 0.30` — published beacon CoV thresholds cluster
  between 0.2 and 0.4; 0.3 sits in the middle and produces
  ~5% false-positive rate on synthetic mixed traffic.
- `min_period_seconds = 1.0` — sub-second beacons are
  retransmits or rapid connection storms, not C2.

**Severity escalation** (deterministic):
- `count >= 50 AND cov <= 0.10` → CRITICAL (long-running,
  highly periodic — automated tooling).
- `count >= 20 AND cov <= 0.20` → HIGH.
- otherwise MEDIUM.

**Confidence** (in [0, 1]):
- base 0.5; +min(0.3, count/100); +0.2 * (1 - cov/max_cov).

**Filters** (mirrors port_scan):
- ACCEPT-only; REJECT/NODATA/SKIPDATA records skipped.
- loopback / link-local / unspecified src_ip skipped — these aren't
  external actors and a 60s ARP-cache refresh from the link-local
  address would otherwise flag as beacon.
"""

from __future__ import annotations

import ipaddress
import math
import statistics
from collections import defaultdict
from collections.abc import Sequence

from network_threat.schemas import (
    Beacon,
    Detection,
    FindingType,
    FlowRecord,
    Severity,
    short_ip_token,
)

_DETECTOR_ID = "beacon@0.1.0"

DEFAULT_MIN_COUNT = 5
DEFAULT_MAX_COV = 0.30
DEFAULT_MIN_PERIOD_SECONDS = 1.0


def detect_beacon(
    flow_records: Sequence[FlowRecord],
    *,
    min_count: int = DEFAULT_MIN_COUNT,
    max_cov: float = DEFAULT_MAX_COV,
    min_period_seconds: float = DEFAULT_MIN_PERIOD_SECONDS,
) -> tuple[Detection, ...]:
    """Walk FlowRecords for beacon patterns and emit Detections.

    `flow_records` may be in any order; the detector sorts internally
    per (src, dst, port) group.
    """
    if min_count < 3:
        raise ValueError(f"min_count must be >= 3 for variance; got {min_count}")
    if max_cov <= 0:
        raise ValueError(f"max_cov must be > 0; got {max_cov}")
    if min_period_seconds <= 0:
        raise ValueError(f"min_period_seconds must be > 0; got {min_period_seconds}")

    by_pair: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    for fr in flow_records:
        if fr.action != "ACCEPT":
            continue
        if _is_filtered_src(fr.src_ip):
            continue
        by_pair[(fr.src_ip, fr.dst_ip, fr.dst_port)].append(fr)

    out: list[Detection] = []
    seq_by_src: dict[str, int] = defaultdict(int)
    for (src, dst, port), records in by_pair.items():
        if len(records) < min_count:
            continue
        records.sort(key=lambda r: r.start_time)
        beacon = _build_beacon(src, dst, port, records)
        if beacon is None:
            continue
        if beacon.period_seconds < min_period_seconds:
            continue
        cov = _cov(beacon)
        if cov > max_cov:
            continue
        seq_by_src[src] += 1
        out.append(_to_detection(beacon, cov=cov, sequence=seq_by_src[src]))
    return tuple(out)


def _is_filtered_src(src_ip: str) -> bool:
    if not src_ip or src_ip == "-":
        return True
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    return addr.is_unspecified or addr.is_loopback or addr.is_link_local


def _build_beacon(
    src: str,
    dst: str,
    port: int,
    records: list[FlowRecord],
) -> Beacon | None:
    """Compute (period, variance, confidence) over a sorted run of connections."""
    times = [r.start_time for r in records]
    inter_arrivals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    if not inter_arrivals:
        return None
    period = statistics.mean(inter_arrivals)
    variance = statistics.variance(inter_arrivals) if len(inter_arrivals) > 1 else 0.0
    cov = math.sqrt(variance) / period if period > 0 else math.inf
    confidence = _confidence(len(records), cov=cov)
    return Beacon(
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        connection_count=len(records),
        period_seconds=period,
        variance_seconds=variance,
        confidence=confidence,
        first_seen=times[0],
        last_seen=times[-1],
    )


def _cov(beacon: Beacon) -> float:
    if beacon.period_seconds <= 0:
        return math.inf
    return math.sqrt(beacon.variance_seconds) / beacon.period_seconds


def _confidence(count: int, *, cov: float) -> float:
    base = 0.5
    count_bonus = min(0.3, count / 100.0)
    cov_bonus = 0.2 * max(0.0, 1.0 - (cov / DEFAULT_MAX_COV))
    return max(0.0, min(1.0, base + count_bonus + cov_bonus))


def _to_detection(beacon: Beacon, *, cov: float, sequence: int) -> Detection:
    severity = _severity_for(beacon.connection_count, cov=cov)
    finding_id = f"NETWORK-BEACON-{short_ip_token(beacon.src_ip)}-{sequence:03d}-periodic"
    return Detection(
        finding_type=FindingType.BEACON,
        severity=severity,
        title=(
            f"Beacon from {beacon.src_ip} to {beacon.dst_ip}:{beacon.dst_port} — "
            f"{beacon.connection_count} hits, period {beacon.period_seconds:.1f}s"
        ),
        description=(
            f"Periodic connection pattern: {beacon.connection_count} connections "
            f"at mean period {beacon.period_seconds:.2f}s, CoV {cov:.3f} "
            f"(threshold {DEFAULT_MAX_COV})."
        ),
        detector_id=_DETECTOR_ID,
        src_ip=beacon.src_ip,
        dst_ip=beacon.dst_ip,
        detected_at=beacon.first_seen,
        evidence={
            "finding_id": finding_id,
            "src_ip": beacon.src_ip,
            "dst_ip": beacon.dst_ip,
            "dst_port": beacon.dst_port,
            "connection_count": beacon.connection_count,
            "period_seconds": round(beacon.period_seconds, 3),
            "variance_seconds": round(beacon.variance_seconds, 6),
            "coefficient_of_variation": round(cov, 4),
            "confidence": round(beacon.confidence, 3),
            "first_seen": beacon.first_seen.isoformat(),
            "last_seen": beacon.last_seen.isoformat(),
        },
    )


def _severity_for(count: int, *, cov: float) -> Severity:
    if count >= 50 and cov <= 0.10:
        return Severity.CRITICAL
    if count >= 20 and cov <= 0.20:
        return Severity.HIGH
    return Severity.MEDIUM


__all__ = [
    "DEFAULT_MAX_COV",
    "DEFAULT_MIN_COUNT",
    "DEFAULT_MIN_PERIOD_SECONDS",
    "detect_beacon",
]
