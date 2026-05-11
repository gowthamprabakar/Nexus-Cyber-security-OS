"""Tests for `runtime_threat.tools.falco.falco_alerts_read`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from runtime_threat.tools.falco import (
    FALCO_PRIORITIES,
    FalcoAlert,
    FalcoError,
    falco_alerts_read,
)


def _write_jsonl(tmp_path: Path, lines: list[dict[str, Any] | str]) -> Path:
    path = tmp_path / "falco.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for line in lines:
            if isinstance(line, str):
                handle.write(line + "\n")
            else:
                handle.write(json.dumps(line) + "\n")
    return path


def _falco_alert_payload(
    *,
    time: str = "2026-05-11T12:00:00.123Z",
    rule: str = "Terminal shell in container",
    priority: str = "Warning",
    output: str = "A shell was used as the entrypoint",
    output_fields: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "time": time,
        "rule": rule,
        "priority": priority,
        "output": output,
        "output_fields": output_fields or {"container.id": "abc123", "proc.cmdline": "/bin/sh"},
        "tags": tags or ["container", "shell", "process"],
    }


# ---------------------------- happy path ---------------------------------


@pytest.mark.asyncio
async def test_reads_single_alert(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_falco_alert_payload()])
    alerts = await falco_alerts_read(feed_path=path)

    assert len(alerts) == 1
    assert isinstance(alerts[0], FalcoAlert)
    assert alerts[0].rule == "Terminal shell in container"
    assert alerts[0].priority == "Warning"
    assert alerts[0].time == datetime(2026, 5, 11, 12, 0, 0, 123_000, tzinfo=UTC)
    assert alerts[0].output_fields["container.id"] == "abc123"
    assert alerts[0].tags == ("container", "shell", "process")


@pytest.mark.asyncio
async def test_reads_multiple_alerts(tmp_path: Path) -> None:
    payloads = [
        _falco_alert_payload(rule=f"rule-{i}", time=f"2026-05-11T12:00:{i:02d}Z") for i in range(5)
    ]
    path = _write_jsonl(tmp_path, list(payloads))
    alerts = await falco_alerts_read(feed_path=path)
    assert {a.rule for a in alerts} == {f"rule-{i}" for i in range(5)}


@pytest.mark.asyncio
async def test_returns_tuple_not_list(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_falco_alert_payload()])
    alerts = await falco_alerts_read(feed_path=path)
    assert isinstance(alerts, tuple)


@pytest.mark.asyncio
async def test_empty_file_returns_empty_tuple(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    alerts = await falco_alerts_read(feed_path=path)
    assert alerts == ()


@pytest.mark.asyncio
async def test_accepts_string_path(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_falco_alert_payload()])
    alerts = await falco_alerts_read(feed_path=str(path))
    assert len(alerts) == 1


# ---------------------------- malformed-line tolerance -------------------


@pytest.mark.asyncio
async def test_skips_malformed_json_line(tmp_path: Path) -> None:
    """A single bad line must not stop the reader."""
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write(json.dumps(_falco_alert_payload(rule="good-1")) + "\n")
        h.write("{not valid json\n")
        h.write(json.dumps(_falco_alert_payload(rule="good-2")) + "\n")

    alerts = await falco_alerts_read(feed_path=path)
    assert {a.rule for a in alerts} == {"good-1", "good-2"}


@pytest.mark.asyncio
async def test_skips_non_object_json(tmp_path: Path) -> None:
    """`json.loads` returning a list/number/string must be skipped silently."""
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write("[1, 2, 3]\n")
        h.write('"just a string"\n')
        h.write(json.dumps(_falco_alert_payload()) + "\n")

    alerts = await falco_alerts_read(feed_path=path)
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_skips_alerts_with_missing_required_fields(tmp_path: Path) -> None:
    """Alerts missing `time` or `rule` are skipped (no partial alerts emitted)."""
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write(json.dumps({"rule": "no-time-here", "priority": "Warning"}) + "\n")
        h.write(json.dumps({"time": "2026-05-11T12:00:00Z", "priority": "Warning"}) + "\n")
        h.write(json.dumps(_falco_alert_payload(rule="valid")) + "\n")

    alerts = await falco_alerts_read(feed_path=path)
    assert [a.rule for a in alerts] == ["valid"]


@pytest.mark.asyncio
async def test_blank_lines_skipped(tmp_path: Path) -> None:
    path = tmp_path / "feed.jsonl"
    with path.open("w") as h:
        h.write("\n\n")
        h.write(json.dumps(_falco_alert_payload(rule="good")) + "\n")
        h.write("   \n")

    alerts = await falco_alerts_read(feed_path=path)
    assert [a.rule for a in alerts] == ["good"]


# ---------------------------- error path ---------------------------------


@pytest.mark.asyncio
async def test_missing_feed_raises_falco_error(tmp_path: Path) -> None:
    with pytest.raises(FalcoError, match="falco feed missing"):
        await falco_alerts_read(feed_path=tmp_path / "does-not-exist.jsonl")


# ---------------------------- shape invariants ---------------------------


def test_falco_alert_is_frozen() -> None:
    import dataclasses

    alert = FalcoAlert(
        time=datetime.now(UTC),
        rule="x",
        priority="Warning",
        output="o",
        output_fields={},
        tags=(),
    )
    assert dataclasses.is_dataclass(alert)
    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.rule = "mutated"  # type: ignore[misc]


def test_falco_priorities_constant_contains_canonical_set() -> None:
    """The eight Falco priority levels per upstream docs."""
    expected = {
        "Emergency",
        "Alert",
        "Critical",
        "Error",
        "Warning",
        "Notice",
        "Informational",
        "Debug",
    }
    assert frozenset(expected) == FALCO_PRIORITIES
