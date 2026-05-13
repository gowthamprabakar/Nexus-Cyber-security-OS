"""Tests for `network_threat.tools.suricata_reader`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from network_threat.schemas import SuricataAlertSeverity
from network_threat.tools.suricata_reader import SuricataReaderError, read_suricata_alerts


def _alert(
    *,
    timestamp: str = "2026-05-13T12:00:00.123456+0000",
    src_ip: str = "203.0.113.5",
    dst_ip: str = "10.0.1.42",
    sig_id: int = 2001234,
    severity: int = 1,
) -> str:
    return json.dumps(
        {
            "timestamp": timestamp,
            "flow_id": 1234567890,
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": 54321,
            "dest_ip": dst_ip,
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sig_id,
                "rev": 2,
                "signature": "ET MALWARE Suspicious TLS",
                "category": "A Network Trojan was Detected",
                "severity": severity,
            },
        }
    )


@pytest.mark.asyncio
async def test_read_suricata_alerts_happy_path(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(_alert() + "\n")

    out = await read_suricata_alerts(path=eve)

    assert len(out) == 1
    a = out[0]
    assert a.signature_id == 2001234
    assert a.severity == SuricataAlertSeverity.HIGH
    assert a.src_ip == "203.0.113.5"
    assert a.dst_ip == "10.0.1.42"
    assert a.dst_port == 443
    assert a.protocol == "TCP"
    assert a.rev == 2
    assert a.unmapped["flow_id"] == 1234567890
    assert a.unmapped["alert_action"] == "allowed"
    assert a.timestamp == datetime(2026, 5, 13, 12, 0, 0, 123456, tzinfo=UTC)


@pytest.mark.asyncio
async def test_read_suricata_alerts_drops_non_alert_events(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    lines = [
        json.dumps({"event_type": "dns", "timestamp": "2026-05-13T12:00:00+0000"}),
        json.dumps({"event_type": "flow", "timestamp": "2026-05-13T12:00:00+0000"}),
        _alert(),
        json.dumps({"event_type": "http", "timestamp": "2026-05-13T12:00:00+0000"}),
    ]
    eve.write_text("\n".join(lines) + "\n")

    out = await read_suricata_alerts(path=eve)

    assert len(out) == 1
    assert out[0].signature_id == 2001234


@pytest.mark.asyncio
async def test_read_suricata_alerts_drops_malformed_lines(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            [
                "not json at all",
                "{bad json",
                _alert(sig_id=1001),
                "[]",  # not a dict
                "null",
            ]
        )
        + "\n"
    )

    out = await read_suricata_alerts(path=eve)

    assert len(out) == 1
    assert out[0].signature_id == 1001


@pytest.mark.asyncio
async def test_read_suricata_alerts_handles_empty_lines(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("\n\n" + _alert() + "\n\n\n")

    out = await read_suricata_alerts(path=eve)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_read_suricata_alerts_missing_alert_blob_dropped(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps({"event_type": "alert", "timestamp": "2026-05-13T12:00:00+0000"}))

    out = await read_suricata_alerts(path=eve)
    assert out == ()


@pytest.mark.asyncio
async def test_read_suricata_alerts_z_form_timestamp(tmp_path: Path) -> None:
    """Some Suricata builds emit ISO with 'Z' instead of '+0000'."""
    eve = tmp_path / "eve.json"
    eve.write_text(_alert(timestamp="2026-05-13T12:00:00.000000Z"))

    out = await read_suricata_alerts(path=eve)
    assert len(out) == 1
    assert out[0].timestamp == datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_read_suricata_alerts_invalid_severity_dropped(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(_alert(severity=99))

    out = await read_suricata_alerts(path=eve)
    assert out == ()


@pytest.mark.asyncio
async def test_read_suricata_alerts_severity_levels(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            [
                _alert(sig_id=1, severity=1),
                _alert(sig_id=2, severity=2),
                _alert(sig_id=3, severity=3),
            ]
        )
    )

    out = await read_suricata_alerts(path=eve)

    assert len(out) == 3
    assert out[0].severity == SuricataAlertSeverity.HIGH
    assert out[1].severity == SuricataAlertSeverity.MEDIUM
    assert out[2].severity == SuricataAlertSeverity.LOW


@pytest.mark.asyncio
async def test_read_suricata_alerts_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SuricataReaderError, match="not found"):
        await read_suricata_alerts(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_read_suricata_alerts_path_is_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(SuricataReaderError, match="not a file"):
        await read_suricata_alerts(path=tmp_path)
