"""Tests for `network_threat.tools.vpc_flow_reader`."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime
from pathlib import Path

import pytest
from network_threat.tools.vpc_flow_reader import VpcFlowReaderError, read_vpc_flow_logs

_START_EPOCH = int(datetime(2026, 5, 13, 10, 0, 0, tzinfo=UTC).timestamp())
_END_EPOCH = _START_EPOCH + 60


def _v2_line(
    *,
    src: str = "10.0.1.42",
    dst: str = "203.0.113.5",
    srcport: int = 12345,
    dstport: int = 443,
    protocol: int = 6,
    packets: int = 15,
    bytes_: int = 8192,
    start: int = _START_EPOCH,
    end: int = _END_EPOCH,
    action: str = "ACCEPT",
    log_status: str = "OK",
    account: str = "123456789012",
    iface: str = "eni-abc123",
) -> str:
    """Default v2 14-field record."""
    return (
        f"2 {account} {iface} {src} {dst} {srcport} {dstport} "
        f"{protocol} {packets} {bytes_} {start} {end} {action} {log_status}"
    )


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_v2_default_format(tmp_path: Path) -> None:
    flog = tmp_path / "flow.log"
    flog.write_text(_v2_line() + "\n")

    out = await read_vpc_flow_logs(path=flog)

    assert len(out) == 1
    r = out[0]
    assert r.src_ip == "10.0.1.42"
    assert r.dst_ip == "203.0.113.5"
    assert r.src_port == 12345
    assert r.dst_port == 443
    assert r.protocol == 6
    assert r.packets == 15
    assert r.bytes_transferred == 8192
    assert r.action == "ACCEPT"
    assert r.log_status == "OK"
    assert r.account_id == "123456789012"
    assert r.interface_id == "eni-abc123"
    assert r.start_time == datetime(2026, 5, 13, 10, 0, 0, tzinfo=UTC)
    assert r.end_time == datetime(2026, 5, 13, 10, 1, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_with_header_v5(tmp_path: Path) -> None:
    """Header line drives the field map; v5 includes vpc-id."""
    flog = tmp_path / "flow.log"
    header = (
        "version vpc-id subnet-id instance-id interface-id account-id "
        "type srcaddr dstaddr srcport dstport pkt-srcaddr pkt-dstaddr "
        "protocol bytes packets start end action tcp-flags log-status"
    )
    # Match header order:
    record = (
        f"5 vpc-abc123 subnet-xyz i-1234 eni-abc123 123456789012 "
        f"IPv4 10.0.1.42 203.0.113.5 12345 443 10.0.1.42 203.0.113.5 "
        f"6 8192 15 {_START_EPOCH} {_END_EPOCH} ACCEPT 19 OK"
    )
    flog.write_text(f"{header}\n{record}\n")

    out = await read_vpc_flow_logs(path=flog)

    assert len(out) == 1
    r = out[0]
    assert r.src_ip == "10.0.1.42"
    assert r.dst_ip == "203.0.113.5"
    assert r.vpc_id == "vpc-abc123"
    assert r.account_id == "123456789012"
    assert r.interface_id == "eni-abc123"
    assert r.action == "ACCEPT"
    assert r.log_status == "OK"


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_gzipped(tmp_path: Path) -> None:
    flog = tmp_path / "flow.log.gz"
    body = (_v2_line() + "\n").encode("utf-8")
    flog.write_bytes(gzip.compress(body))

    out = await read_vpc_flow_logs(path=flog)

    assert len(out) == 1
    assert out[0].src_ip == "10.0.1.42"


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_skips_malformed(tmp_path: Path) -> None:
    flog = tmp_path / "flow.log"
    flog.write_text(
        "\n".join(
            [
                "too few fields",
                "2 acct iface 1.2.3.4 5.6.7.8 80 80 6 1 1 1 1 ACCEPT OK",  # OK
                "garbage line with not enough tokens",
            ]
        )
        + "\n"
    )

    out = await read_vpc_flow_logs(path=flog)

    assert len(out) == 1
    assert out[0].src_ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_unknown_action_collapses_to_nodata(tmp_path: Path) -> None:
    flog = tmp_path / "flow.log"
    flog.write_text(_v2_line(action="UNKNOWN") + "\n")

    out = await read_vpc_flow_logs(path=flog)
    assert len(out) == 1
    assert out[0].action == "NODATA"


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_dash_collapses_to_zeros(tmp_path: Path) -> None:
    """AWS uses `-` for SKIPDATA records; numeric fields collapse to 0."""
    flog = tmp_path / "flow.log"
    flog.write_text("2 - - - - - - - - - - - SKIPDATA SKIPDATA\n")

    out = await read_vpc_flow_logs(path=flog)
    assert len(out) == 1
    r = out[0]
    assert r.packets == 0
    assert r.bytes_transferred == 0
    assert r.account_id == ""
    assert r.interface_id == ""
    assert r.action == "SKIPDATA"


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_handles_blank_lines(tmp_path: Path) -> None:
    flog = tmp_path / "flow.log"
    flog.write_text("\n\n" + _v2_line() + "\n\n\n")

    out = await read_vpc_flow_logs(path=flog)
    assert len(out) == 1


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_extra_trailing_fields_preserved(tmp_path: Path) -> None:
    """v3/v4 trailing fields beyond v2 map land under `unmapped.extra_<i>`."""
    flog = tmp_path / "flow.log"
    flog.write_text(_v2_line() + " EXTRA1 EXTRA2\n")  # 16 fields total

    out = await read_vpc_flow_logs(path=flog)
    assert len(out) == 1
    assert out[0].unmapped == {"extra_14": "EXTRA1", "extra_15": "EXTRA2"}


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(VpcFlowReaderError, match="not found"):
        await read_vpc_flow_logs(path=tmp_path / "missing.log")


@pytest.mark.asyncio
async def test_read_vpc_flow_logs_path_is_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(VpcFlowReaderError, match="not a file"):
        await read_vpc_flow_logs(path=tmp_path)
