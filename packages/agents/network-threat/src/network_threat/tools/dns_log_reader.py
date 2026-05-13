"""`read_dns_logs` — filesystem ingest for DNS query log files.

Supports two formats with automatic dispatch:

- **BIND query log** — text lines from `named` query logging (the
  canonical Unix DNS server format).
- **AWS Route 53 Resolver Query Logs** — ndjson, one record per line
  in the AWS-published schema.

The reader peeks the first non-blank line: if it parses as a JSON
object, the file is treated as Route 53 format; otherwise BIND text.
This avoids extension-based dispatch (Route 53 files are sometimes
plain `.log`; operator pipelines vary).

Per ADR-005 the filesystem read happens on `asyncio.to_thread`; the
wrapper is `async` for TaskGroup fan-out. Forgiving on every failure
mode (mirrors F.6 + Suricata + VPC readers).

Normalisation rules:
- `query_name` lowercased; one trailing dot stripped.
- BIND timestamp parsed as `%d-%b-%Y %H:%M:%S.%f` (the default format);
  unknown TZ → UTC.
- Route 53 `query_timestamp` parsed via `datetime.fromisoformat` after
  `Z` → `+00:00` normalisation.
- `query_type` defaults to `A`, `rcode` defaults to `NOERROR`.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from network_threat.schemas import DnsEvent, DnsEventKind

_LineParser = Callable[[str], DnsEvent | None]


class DnsLogReaderError(RuntimeError):
    """The DNS log feed could not be read."""


# BIND query log line:
# 13-May-2026 12:00:00.123 queries: info: client @0x... 10.0.1.42#54321 (malicious.xyz):
#                                   query: malicious.xyz IN A +E(0)K (10.0.1.1)
_BIND_LINE = re.compile(
    r"^(?P<date>\d{2}-[A-Za-z]{3}-\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d{1,6})\s+"
    r"queries:\s+\w+:\s+client\s+(?:@\S+\s+)?"
    r"(?P<src_ip>[0-9a-fA-F:.]+)"
    r"(?:#(?P<src_port>\d+))?"
    r"\s+\([^)]*\):\s+query:\s+"
    r"(?P<qname>\S+)"
    r"\s+(?P<qclass>\S+)\s+(?P<qtype>\S+)"
    r".*?(?:\((?P<resolver>[0-9a-fA-F:.]+)\))?\s*$"
)


async def read_dns_logs(*, path: Path) -> tuple[DnsEvent, ...]:
    """Read a DNS query log file (BIND or Route 53 format) and return parsed events."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[DnsEvent, ...]:
    if not path.exists():
        raise DnsLogReaderError(f"dns log not found: {path}")
    if not path.is_file():
        raise DnsLogReaderError(f"dns log is not a file: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as f:
        lines = [ln.rstrip("\n") for ln in f]

    first = _first_non_blank(lines)
    parser = _select_parser(first)

    events: list[DnsEvent] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        event = parser(stripped)
        if event is not None:
            events.append(event)
    return tuple(events)


def _first_non_blank(lines: list[str]) -> str:
    for ln in lines:
        stripped = ln.strip()
        if stripped:
            return stripped
    return ""


def _select_parser(first_line: str) -> _LineParser:
    if not first_line:
        return _parse_bind_line
    try:
        candidate = json.loads(first_line)
    except json.JSONDecodeError:
        return _parse_bind_line
    if isinstance(candidate, dict):
        return _parse_route53_line
    return _parse_bind_line


# ---------------------------- BIND parser --------------------------------


def _parse_bind_line(raw: str) -> DnsEvent | None:
    m = _BIND_LINE.match(raw)
    if m is None:
        return None
    ts = _parse_bind_timestamp(m.group("date"), m.group("time"))
    if ts is None:
        return None
    qname = _normalise_qname(m.group("qname"))
    if not qname:
        return None
    try:
        return DnsEvent(
            timestamp=ts,
            kind=DnsEventKind.QUERY,
            query_name=qname,
            query_type=m.group("qtype") or "A",
            src_ip=m.group("src_ip") or "",
            resolver_endpoint=m.group("resolver") or "",
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _parse_bind_timestamp(date_part: str, time_part: str) -> datetime | None:
    """BIND uses `dd-Mon-yyyy HH:MM:SS.fff` (default `query-source-format`)."""
    try:
        # `%f` parses 1-6 digit subseconds.
        return datetime.strptime(f"{date_part} {time_part}", "%d-%b-%Y %H:%M:%S.%f").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None


# ---------------------------- Route 53 parser ----------------------------


def _parse_route53_line(raw: str) -> DnsEvent | None:
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None
    timestamp = _parse_iso_timestamp(record.get("query_timestamp"))
    if timestamp is None:
        return None
    qname = _normalise_qname(record.get("query_name"))
    if not qname:
        return None
    answers = _parse_answers(record.get("answers"))
    kind = DnsEventKind.RESPONSE if answers else DnsEventKind.QUERY
    try:
        return DnsEvent(
            timestamp=timestamp,
            kind=kind,
            query_name=qname,
            query_type=str(record.get("query_type") or "A"),
            src_ip=str(record.get("srcaddr") or ""),
            resolver_endpoint=str(record.get("vpc_id") or ""),
            rcode=str(record.get("rcode") or "NOERROR"),
            answers=answers,
            unmapped=_collect_unmapped(record),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_answers(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value:
        if isinstance(item, dict):
            rdata = item.get("Rdata") or item.get("rdata")
            if isinstance(rdata, str):
                out.append(rdata)
        elif isinstance(item, str):
            out.append(item)
    return tuple(out)


def _collect_unmapped(record: dict[str, Any]) -> dict[str, Any]:
    """Preserve interesting Route 53 fields not in the typed shape."""
    out: dict[str, Any] = {}
    for key in ("account_id", "region", "transport", "srcids", "version"):
        if key in record:
            out[key] = record[key]
    return out


# ---------------------------- helpers ------------------------------------


def _normalise_qname(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    return name


__all__ = ["DnsLogReaderError", "read_dns_logs"]
