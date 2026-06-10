"""Zeek live event normalization (D.4 v0.2 Task 6).

Turns raw Zeek log records into typed events: ``conn`` → `ZeekConn`, ``dns`` →
`DnsEvent` (the **same** schema the offline DNS reader produces, so the DNS detectors
stay byte-identical). The receive timestamp is **caller-provided** (`received_at`) for
determinism; Zeek's own ``ts`` (epoch seconds) is used when present.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from network_threat.schemas import DnsEvent, DnsEventKind


@dataclass(frozen=True, slots=True)
class ZeekConn:
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = ""


def _zeek_ts(raw: dict[str, Any], received_at: datetime) -> datetime:
    ts = raw.get("ts")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=UTC)
    return received_at


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_zeek_conn(raw: dict[str, Any], *, received_at: datetime) -> ZeekConn | None:
    """Normalize a Zeek ``conn`` record → `ZeekConn`. Returns `None` if either endpoint
    IP is missing."""
    src_ip = str(raw.get("id.orig_h", ""))
    dst_ip = str(raw.get("id.resp_h", ""))
    if not src_ip or not dst_ip:
        return None
    return ZeekConn(
        uid=str(raw.get("uid", "")),
        src_ip=src_ip,
        src_port=_int(raw.get("id.orig_p")),
        dst_ip=dst_ip,
        dst_port=_int(raw.get("id.resp_p")),
        proto=str(raw.get("proto", "")),
        duration=float(raw.get("duration", 0.0) or 0.0),
        orig_bytes=_int(raw.get("orig_bytes")),
        resp_bytes=_int(raw.get("resp_bytes")),
        conn_state=str(raw.get("conn_state", "")),
    )


def normalize_zeek_dns(raw: dict[str, Any], *, received_at: datetime) -> DnsEvent | None:
    """Normalize a Zeek ``dns`` record → `DnsEvent` (same schema as the offline reader).
    Returns `None` if there is no query name."""
    query = str(raw.get("query", "")).strip().lower().rstrip(".")
    if not query:
        return None
    rcode = raw.get("rcode_name")
    kind = DnsEventKind.RESPONSE if rcode is not None else DnsEventKind.QUERY
    try:
        return DnsEvent(
            timestamp=_zeek_ts(raw, received_at),
            kind=kind,
            query_name=query,
            query_type=str(raw.get("qtype_name", "A")) or "A",
            src_ip=str(raw.get("id.orig_h", "")),
            rcode=str(rcode) if rcode is not None else "NOERROR",
        )
    except (ValidationError, ValueError, TypeError):
        return None


def normalize_zeek_event(
    raw: dict[str, Any], *, received_at: datetime
) -> ZeekConn | DnsEvent | None:
    """Dispatch a Zeek record by its ``_path`` (``conn`` / ``dns``)."""
    path = raw.get("_path")
    if path == "conn":
        return normalize_zeek_conn(raw, received_at=received_at)
    if path == "dns":
        return normalize_zeek_dns(raw, received_at=received_at)
    return None
