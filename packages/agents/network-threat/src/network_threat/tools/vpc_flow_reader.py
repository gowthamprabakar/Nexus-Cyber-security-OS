"""`read_vpc_flow_logs` — filesystem ingest for AWS VPC Flow Logs.

Supports v2 (default), v3, v4, and v5 formats. The reader detects the
field layout from the file's header line (a `version`-bearing tokens
line) or falls back to the v2 default field map if no header is present.

Per ADR-005 the filesystem read happens on `asyncio.to_thread` (file
I/O + gzip decompression are sync); the wrapper is `async` for
TaskGroup fan-out.

**Gzipped + plaintext both supported.** AWS S3 delivers VPC Flow Logs
gzipped (`.log.gz`); operators occasionally hand-decompress for ad-hoc
analysis. We detect the gzip magic bytes (`\\x1f\\x8b`) rather than
relying on the extension — Phase 1c live S3 ingest will pass file
handles directly.

**Forgiving** on malformed records — a single bad line is dropped, not
the whole file (mirrors F.6 + Suricata readers). Records with
`log_status != "OK"` are still parsed (the operator may want to see
NODATA windows in the report), but byte/packet counts of `-` collapse
to 0.
"""

from __future__ import annotations

import asyncio
import gzip
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from network_threat.schemas import FlowRecord

# AWS v2 default field order (no header in the file).
_V2_DEFAULT_FIELDS: tuple[str, ...] = (
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
)

_GZIP_MAGIC = b"\x1f\x8b"


class VpcFlowReaderError(RuntimeError):
    """The VPC Flow Logs feed could not be read."""


async def read_vpc_flow_logs(*, path: Path) -> tuple[FlowRecord, ...]:
    """Read an AWS VPC Flow Logs file (plaintext or gzipped) and return parsed records."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[FlowRecord, ...]:
    if not path.exists():
        raise VpcFlowReaderError(f"vpc flow logs not found: {path}")
    if not path.is_file():
        raise VpcFlowReaderError(f"vpc flow logs is not a file: {path}")

    with path.open("rb") as fh:
        head = fh.read(2)
    is_gzip = head == _GZIP_MAGIC

    if is_gzip:
        with gzip.open(path, mode="rt", encoding="utf-8") as f:
            return _parse_stream(f)
    with path.open("r", encoding="utf-8") as f:
        return _parse_stream(f)


def _parse_stream(stream: Any) -> tuple[FlowRecord, ...]:
    records: list[FlowRecord] = []
    fields: tuple[str, ...] | None = None
    for line in stream:
        stripped = line.strip()
        if not stripped:
            continue
        tokens = stripped.split()
        # First non-blank line: header detection.
        if fields is None:
            if _is_header(tokens):
                fields = tuple(t.lower() for t in tokens)
                continue
            fields = _V2_DEFAULT_FIELDS
        record = _try_parse_record(tokens, fields)
        if record is not None:
            records.append(record)
    return tuple(records)


def _is_header(tokens: list[str]) -> bool:
    """A line is a header if it contains the literal field name `version` (case-insensitive)
    and at least 14 tokens (the v2 minimum).
    """
    return len(tokens) >= 14 and any(t.lower() == "version" for t in tokens)


def _try_parse_record(tokens: list[str], fields: tuple[str, ...]) -> FlowRecord | None:
    if len(tokens) < 14:
        return None
    # We tolerate trailing extra fields in v3/v4/v5 by walking the field map
    # up to the shorter length.
    pairs: dict[str, str] = {}
    extra: dict[str, str] = {}
    n = min(len(tokens), len(fields))
    for i in range(n):
        pairs[fields[i]] = tokens[i]
    # Trailing tokens beyond the known field map are preserved as `unmapped.extra_<i>`.
    for i in range(n, len(tokens)):
        extra[f"extra_{i}"] = tokens[i]

    try:
        return FlowRecord(
            src_ip=pairs.get("srcaddr", "-"),
            dst_ip=pairs.get("dstaddr", "-"),
            src_port=_safe_int(pairs.get("srcport")),
            dst_port=_safe_int(pairs.get("dstport")),
            protocol=_safe_int(pairs.get("protocol")),
            bytes_transferred=_safe_int(pairs.get("bytes")),
            packets=_safe_int(pairs.get("packets")),
            start_time=_safe_epoch(pairs.get("start")),
            end_time=_safe_epoch(pairs.get("end")),
            action=_safe_action(pairs.get("action")),
            log_status=pairs.get("log-status", "OK") or "OK",
            account_id=pairs.get("account-id", "") if pairs.get("account-id", "-") != "-" else "",
            interface_id=(
                pairs.get("interface-id", "") if pairs.get("interface-id", "-") != "-" else ""
            ),
            vpc_id=pairs.get("vpc-id", "") if pairs.get("vpc-id", "-") != "-" else "",
            unmapped=dict(extra),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _safe_int(value: str | None) -> int:
    """AWS uses `-` for missing numeric fields (e.g. dropped via skipdata)."""
    if not value or value == "-":
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _safe_epoch(value: str | None) -> datetime:
    """Parse a UNIX epoch (string of seconds). `-` collapses to UTC epoch zero
    so the FlowRecord still validates; downstream detectors filter on
    `log_status` or zero-duration when filtering.
    """
    if not value or value == "-":
        return datetime.fromtimestamp(0, tz=UTC)
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OverflowError):
        return datetime.fromtimestamp(0, tz=UTC)


def _safe_action(value: str | None) -> str:
    """The FlowRecord field is regex-validated against ACCEPT/REJECT/NODATA/SKIPDATA.
    Anything else (including `-`) collapses to `NODATA` so the record still validates.
    """
    if value in {"ACCEPT", "REJECT", "NODATA", "SKIPDATA"}:
        return value
    return "NODATA"


__all__ = ["VpcFlowReaderError", "read_vpc_flow_logs"]
