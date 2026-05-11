"""Falco alerts JSONL reader.

Falco's `json_output` mode emits one alert per line:

    {
      "time": "2026-05-11T12:00:00.123Z",
      "rule": "Terminal shell in container",
      "priority": "Warning",
      "output": "A shell was used as the entrypoint/exec point ...",
      "output_fields": {"container.id": "abc123", ...},
      "tags": ["container", "shell", "process"]
    }

Per ADR-005 the read goes through `asyncio.to_thread` (the filesystem
read is sync). Per the D.3 plan Task 3, malformed lines are silently
skipped — Falco occasionally interleaves stderr-style lines with
properly framed JSON in pathological deployments, and the agent must
not crash on a single bad line.

Live Falco gRPC consumption (long-running stream) is deferred to Phase
1c per the D.3 plan's defers list.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Falco's standard priority levels. Anything outside this set lands in
# the normalizer's UNKNOWN bucket (Severity.INFO) by default.
FALCO_PRIORITIES = frozenset(
    {
        "Emergency",
        "Alert",
        "Critical",
        "Error",
        "Warning",
        "Notice",
        "Informational",
        "Debug",
    }
)


class FalcoError(RuntimeError):
    """Falco feed could not be read."""


@dataclass(frozen=True, slots=True)
class FalcoAlert:
    """One Falco alert, parsed from a single JSONL line."""

    time: datetime
    rule: str
    priority: str
    output: str
    output_fields: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = field(default_factory=tuple)


async def falco_alerts_read(
    *,
    feed_path: Path | str,
    timeout_sec: float = 60.0,
) -> tuple[FalcoAlert, ...]:
    """Read a Falco JSONL feed and return every successfully parsed alert.

    Args:
        feed_path: Path to a Falco JSONL feed (one alert per line).
        timeout_sec: Wall-clock timeout — raises if the read runs long.

    Raises:
        FalcoError: when the feed file is missing or the read exceeds
            `timeout_sec`. Malformed JSON lines inside the feed are
            silently skipped (best-effort consumption).
    """
    path = Path(feed_path)
    if not path.is_file():
        raise FalcoError(f"falco feed missing: {path}")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_read_feed_sync, path),
            timeout=timeout_sec,
        )
    except TimeoutError as exc:
        raise FalcoError(f"falco_alerts_read timed out after {timeout_sec}s") from exc


def _read_feed_sync(path: Path) -> tuple[FalcoAlert, ...]:
    out: list[FalcoAlert] = []
    with path.open("r", encoding="utf-8") as handle:
        for alert in _parse_lines(handle):
            out.append(alert)
    return tuple(out)


def _parse_lines(handle: Iterator[str]) -> Iterator[FalcoAlert]:
    for raw in handle:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        # `time` is required; tolerate missing/malformed and skip
        time_value = _parse_time(obj.get("time"))
        if time_value is None:
            continue
        rule = obj.get("rule")
        if not isinstance(rule, str) or not rule:
            continue

        priority_raw = obj.get("priority", "")
        priority = priority_raw if isinstance(priority_raw, str) else ""

        output = obj.get("output", "")
        output_str = output if isinstance(output, str) else ""

        fields_raw = obj.get("output_fields")
        fields = dict(fields_raw) if isinstance(fields_raw, dict) else {}

        tags_raw = obj.get("tags")
        tags = (
            tuple(str(t) for t in tags_raw if isinstance(t, str))
            if isinstance(tags_raw, list)
            else ()
        )

        yield FalcoAlert(
            time=time_value,
            rule=rule,
            priority=priority,
            output=output_str,
            output_fields=fields,
            tags=tags,
        )


def _parse_time(value: Any) -> datetime | None:
    """Parse Falco's RFC3339-with-millis timestamp; tolerate trailing Z."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


__all__ = ["FALCO_PRIORITIES", "FalcoAlert", "FalcoError", "falco_alerts_read"]
