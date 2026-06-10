"""DNS resolver live normalization (D.4 v0.2 Task 13).

Exposes the offline reader's **BIND query-log** + **Route 53 Resolver query-log** parsers
as live-stream normalizers, so the real-time path can turn a streamed BIND line or a
Route 53 record into the **same** `DnsEvent` the offline path produces (byte-identical;
the DNS detectors stay unchanged). Per **Q5** D.4 emits findings only — D.7 Investigation
+ D.8 Threat-Intel correlate via OCSF 2004 consumption (no direct D.8 dependency).
"""

from __future__ import annotations

import json
from typing import Any

from network_threat.schemas import DnsEvent
from network_threat.tools.dns_log_reader import _parse_bind_line, _parse_route53_line


def normalize_bind_line(line: str) -> DnsEvent | None:
    """Normalize a streamed BIND query-log line → `DnsEvent` (None if malformed)."""
    return _parse_bind_line(line)


def normalize_route53_line(line: str) -> DnsEvent | None:
    """Normalize a Route 53 Resolver query-log ndjson line → `DnsEvent`."""
    return _parse_route53_line(line)


def normalize_route53_record(record: dict[str, Any]) -> DnsEvent | None:
    """Normalize a Route 53 Resolver query-log record (already-parsed dict) → `DnsEvent`."""
    return _parse_route53_line(json.dumps(record))


def normalize_resolver_event(payload: str, *, source: str) -> DnsEvent | None:
    """Dispatch a streamed resolver payload by ``source`` (``bind`` / ``route53``)."""
    if source == "bind":
        return normalize_bind_line(payload)
    if source == "route53":
        return normalize_route53_line(payload)
    return None
