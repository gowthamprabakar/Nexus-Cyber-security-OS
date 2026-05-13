"""`read_suricata_alerts` — filesystem ingest for Suricata eve.json files.

Reads a Suricata `eve.json` ndjson file and converts each `event_type =
"alert"` record into the D.4 `SuricataAlert` wire shape. Per ADR-005
the filesystem read happens in `asyncio.to_thread` (file I/O is sync);
the wrapper is `async` to fit the agent driver's TaskGroup fan-out.

The reader is **forgiving** — mirrors F.6's `audit_jsonl_read`:
malformed lines, non-alert event types, and records missing required
fields are dropped silently rather than aborting the whole ingest.
Operational reality: Suricata occasionally emits partial lines
(rotated tail, partial flush) and a strict reader would jam an entire
investigation on one bad byte.

**Non-alert event types** (`dns`, `flow`, `http`, `tls`, `fileinfo`)
are parsed by their respective readers (D.4 `dns_log_reader` for DNS;
the operator opts to feed Suricata flow output through `vpc_flow_reader`
if useful). v0.1 ignores them here — alerts only.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from network_threat.schemas import SuricataAlert, SuricataAlertSeverity


class SuricataReaderError(RuntimeError):
    """The Suricata eve.json feed could not be read."""


async def read_suricata_alerts(*, path: Path) -> tuple[SuricataAlert, ...]:
    """Read a Suricata eve.json file and return the parsed `alert` events.

    Filesystem read runs on a worker thread (`asyncio.to_thread`) so
    the agent driver can fan it out alongside other ingest tools via
    `asyncio.TaskGroup`.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[SuricataAlert, ...]:
    if not path.exists():
        raise SuricataReaderError(f"suricata eve.json not found: {path}")
    if not path.is_file():
        raise SuricataReaderError(f"suricata eve.json is not a file: {path}")

    alerts: list[SuricataAlert] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            alert = _try_parse_line(stripped)
            if alert is not None:
                alerts.append(alert)
    return tuple(alerts)


def _try_parse_line(raw: str) -> SuricataAlert | None:
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    # We only handle alert events in v0.1.
    if record.get("event_type") != "alert":
        return None

    alert_blob = record.get("alert")
    if not isinstance(alert_blob, dict):
        return None

    timestamp = _parse_timestamp(record.get("timestamp"))
    if timestamp is None:
        return None

    severity = _parse_severity(alert_blob.get("severity"))
    if severity is None:
        return None

    try:
        return SuricataAlert(
            timestamp=timestamp,
            src_ip=str(record.get("src_ip", "")),
            dst_ip=str(record.get("dest_ip", "")),
            src_port=int(record.get("src_port", 0)),
            dst_port=int(record.get("dest_port", 0)),
            protocol=str(record.get("proto", "")),
            signature_id=int(alert_blob.get("signature_id", 0)),
            signature=str(alert_blob.get("signature", "")),
            category=str(alert_blob.get("category", "")),
            severity=severity,
            rev=int(alert_blob.get("rev", 1)),
            unmapped=_collect_unmapped(record, alert_blob),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    """Suricata emits ISO-8601 with `+0000` offset (no colon); also accept Z form."""
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    # Suricata's `+0000` (no colon) is not understood by fromisoformat on py3.10-;
    # py3.11+ accepts it. We normalise to the colon form for safety.
    if len(candidate) >= 5 and candidate[-5] in "+-" and candidate[-3] != ":":
        candidate = candidate[:-2] + ":" + candidate[-2:]
    try:
        return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_severity(value: Any) -> SuricataAlertSeverity | None:
    """Suricata severity is an int (1-3) in the alert blob; stringify to enum."""
    if value is None:
        return None
    try:
        return SuricataAlertSeverity(str(int(value)))
    except (ValueError, TypeError):
        return None


def _collect_unmapped(record: dict[str, Any], alert_blob: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting fields not in the typed shape (flow_id, tx_id, etc.)."""
    out: dict[str, Any] = {}
    for key in ("flow_id", "tx_id", "in_iface", "vlan", "community_id"):
        if key in record:
            out[key] = record[key]
    action = alert_blob.get("action")
    if action is not None:
        out["alert_action"] = action
    return out


__all__ = ["SuricataReaderError", "read_suricata_alerts"]
