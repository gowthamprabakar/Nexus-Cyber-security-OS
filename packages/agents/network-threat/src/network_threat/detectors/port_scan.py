"""`detect_port_scan` — connection-rate heuristic over FlowRecord input.

Pure-function detector (no I/O, no async). Groups flow records by
`src_ip` and walks a sliding window over their start times; emits one
`Detection` per (src_ip, window) where the count of distinct dst_ports
exceeds `min_distinct_ports`.

**Defaults** (per Q6 of the plan):
- `min_distinct_ports = 50` — Wiz/Suricata baseline; below this is noise.
- `window_seconds = 60` — bounded enough for adjacent flow records to
  share a window, wide enough to catch human-paced reconnaissance.

**Severity escalation** (deterministic, no LLM):
- `distinct_ports >= 200` → CRITICAL (likely automated scanner).
- `distinct_ports >= 100` → HIGH.
- `distinct_ports >= min_distinct_ports` → MEDIUM.

**Loopback + zero-IP suppression.** A FlowRecord with src_ip in
`0.0.0.0`, `127.0.0.0/8`, or `169.254.0.0/16` (link-local) is skipped —
these are not external actors and a high port count from one of them
indicates a misconfiguration, not a threat.

**ACCEPT-only filter.** Only `action="ACCEPT"` records count toward the
detection. REJECT counts come from outbound traffic to non-existent
ports — they're a sign of misconfigured *clients*, not scanners.
NODATA/SKIPDATA records carry no port detail.

Evidence captured per detection:
- `src_ip`, `distinct_ports` (count), `window_seconds`, `ports_sampled`
  (first 10 ports, sorted), `window_start`, `window_end`.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Sequence

from network_threat.schemas import (
    Detection,
    FindingType,
    FlowRecord,
    Severity,
    short_ip_token,
)

_DETECTOR_ID = "port_scan@0.1.0"

DEFAULT_MIN_DISTINCT_PORTS = 50
DEFAULT_WINDOW_SECONDS = 60


def detect_port_scan(
    flow_records: Sequence[FlowRecord],
    *,
    min_distinct_ports: int = DEFAULT_MIN_DISTINCT_PORTS,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[Detection, ...]:
    """Walk FlowRecords for port-scan patterns and emit Detections.

    `flow_records` may be in any order; the detector sorts internally.
    Returns an empty tuple if no source crosses the threshold.
    """
    if min_distinct_ports < 1:
        raise ValueError(f"min_distinct_ports must be >= 1; got {min_distinct_ports}")
    if window_seconds < 1:
        raise ValueError(f"window_seconds must be >= 1; got {window_seconds}")

    by_src: dict[str, list[FlowRecord]] = defaultdict(list)
    for fr in flow_records:
        if fr.action != "ACCEPT":
            continue
        if _is_filtered_src(fr.src_ip):
            continue
        by_src[fr.src_ip].append(fr)

    out: list[Detection] = []
    seq_by_src: dict[str, int] = defaultdict(int)
    for src_ip, records in by_src.items():
        records.sort(key=lambda r: r.start_time)
        for det in _scan_one_source(
            src_ip=src_ip,
            records=records,
            min_distinct_ports=min_distinct_ports,
            window_seconds=window_seconds,
            seq_by_src=seq_by_src,
        ):
            out.append(det)
    return tuple(out)


def _is_filtered_src(src_ip: str) -> bool:
    """Skip 0.0.0.0, loopback, and link-local — these are not external actors."""
    if not src_ip or src_ip == "-":
        return True
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        # Unparseable IP — keep it; the user may want to see it.
        return False
    return addr.is_unspecified or addr.is_loopback or addr.is_link_local


def _scan_one_source(
    *,
    src_ip: str,
    records: list[FlowRecord],
    min_distinct_ports: int,
    window_seconds: int,
    seq_by_src: dict[str, int],
) -> list[Detection]:
    """Sliding-window scan over a single source's flow records."""
    out: list[Detection] = []
    left = 0
    n = len(records)
    while left < n:
        # Find the widest window where (end - start) <= window_seconds.
        right = left
        while right < n and (
            (records[right].start_time - records[left].start_time).total_seconds() <= window_seconds
        ):
            right += 1
        window = records[left:right]
        distinct_ports = {fr.dst_port for fr in window if fr.dst_port > 0}
        if len(distinct_ports) >= min_distinct_ports:
            seq_by_src[src_ip] += 1
            out.append(_build_detection(src_ip, window, distinct_ports, seq_by_src[src_ip]))
            # Skip ahead past this window — don't re-emit overlapping detections.
            left = right
        else:
            left += 1
    return out


def _build_detection(
    src_ip: str,
    window: list[FlowRecord],
    distinct_ports: set[int],
    sequence: int,
) -> Detection:
    """Turn one threshold-crossing window into a Detection."""
    count = len(distinct_ports)
    severity = _severity_for(count)
    ports_sampled = sorted(distinct_ports)[:10]
    window_start = window[0].start_time
    window_end = window[-1].start_time
    window_seconds = (window_end - window_start).total_seconds()
    finding_id = f"NETWORK-PORT_SCAN-{short_ip_token(src_ip)}-{sequence:03d}-rate"
    return Detection(
        finding_type=FindingType.PORT_SCAN,
        severity=severity,
        title=f"Port scan from {src_ip} — {count} distinct dst-ports",
        description=(
            f"Connection-rate heuristic threshold exceeded: {count} distinct "
            f"dst-ports in {window_seconds:.0f}s window."
        ),
        detector_id=_DETECTOR_ID,
        src_ip=src_ip,
        detected_at=window_start,
        evidence={
            "finding_id": finding_id,
            "src_ip": src_ip,
            "distinct_ports": count,
            "window_seconds": int(window_seconds),
            "ports_sampled": ports_sampled,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
        },
    )


def _severity_for(distinct_ports: int) -> Severity:
    if distinct_ports >= 200:
        return Severity.CRITICAL
    if distinct_ports >= 100:
        return Severity.HIGH
    return Severity.MEDIUM


__all__ = [
    "DEFAULT_MIN_DISTINCT_PORTS",
    "DEFAULT_WINDOW_SECONDS",
    "detect_port_scan",
]
