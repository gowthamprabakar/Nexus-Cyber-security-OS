"""Tests for `network_threat.tools.dns_log_reader`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from network_threat.schemas import DnsEventKind
from network_threat.tools.dns_log_reader import DnsLogReaderError, read_dns_logs


def _bind_line(
    *,
    date: str = "13-May-2026",
    time: str = "12:00:00.123",
    src: str = "10.0.1.42",
    src_port: int = 54321,
    qname: str = "malicious.xyz",
    qtype: str = "A",
    resolver: str = "10.0.1.1",
) -> str:
    return (
        f"{date} {time} queries: info: client @0x7f8b8c0028a0 "
        f"{src}#{src_port} ({qname}): query: {qname} IN {qtype} +E(0)K ({resolver})"
    )


def _route53_line(
    *,
    timestamp: str = "2026-05-13T12:00:00Z",
    qname: str = "malicious.xyz.",
    qtype: str = "A",
    src: str = "10.0.1.42",
    vpc_id: str = "vpc-abc123",
    rcode: str = "NOERROR",
    answers: list[dict[str, str]] | None = None,
) -> str:
    record = {
        "version": "1.100000",
        "account_id": "123456789012",
        "region": "us-east-1",
        "vpc_id": vpc_id,
        "query_timestamp": timestamp,
        "query_name": qname,
        "query_type": qtype,
        "query_class": "IN",
        "rcode": rcode,
        "answers": answers or [],
        "srcaddr": src,
        "srcport": "54321",
        "transport": "UDP",
        "srcids": {"instance": "i-1234"},
    }
    return json.dumps(record)


# ---------------------------- BIND format --------------------------------


@pytest.mark.asyncio
async def test_read_dns_logs_bind_happy_path(tmp_path: Path) -> None:
    log = tmp_path / "named.log"
    log.write_text(_bind_line() + "\n")

    out = await read_dns_logs(path=log)

    assert len(out) == 1
    e = out[0]
    assert e.query_name == "malicious.xyz"
    assert e.query_type == "A"
    assert e.src_ip == "10.0.1.42"
    assert e.kind == DnsEventKind.QUERY
    assert e.resolver_endpoint == "10.0.1.1"
    assert e.timestamp == datetime(2026, 5, 13, 12, 0, 0, 123000, tzinfo=UTC)


@pytest.mark.asyncio
async def test_read_dns_logs_bind_normalises_trailing_dot(tmp_path: Path) -> None:
    log = tmp_path / "named.log"
    log.write_text(_bind_line(qname="MALICIOUS.XYZ.") + "\n")

    out = await read_dns_logs(path=log)

    assert len(out) == 1
    assert out[0].query_name == "malicious.xyz"


@pytest.mark.asyncio
async def test_read_dns_logs_bind_drops_unparseable_lines(tmp_path: Path) -> None:
    log = tmp_path / "named.log"
    log.write_text(
        "\n".join(
            [
                "garbage line",
                _bind_line(qname="ok.example"),
                "another garbage line",
            ]
        )
        + "\n"
    )

    out = await read_dns_logs(path=log)
    assert len(out) == 1
    assert out[0].query_name == "ok.example"


@pytest.mark.asyncio
async def test_read_dns_logs_bind_multiple_lines(tmp_path: Path) -> None:
    log = tmp_path / "named.log"
    log.write_text(
        "\n".join(
            [
                _bind_line(qname="one.example"),
                _bind_line(qname="two.example"),
                _bind_line(qname="three.example"),
            ]
        )
        + "\n"
    )

    out = await read_dns_logs(path=log)
    assert [e.query_name for e in out] == ["one.example", "two.example", "three.example"]


# ---------------------------- Route 53 format ----------------------------


@pytest.mark.asyncio
async def test_read_dns_logs_route53_query_no_answers(tmp_path: Path) -> None:
    log = tmp_path / "r53.log"
    log.write_text(_route53_line() + "\n")

    out = await read_dns_logs(path=log)
    assert len(out) == 1
    e = out[0]
    assert e.query_name == "malicious.xyz"
    assert e.query_type == "A"
    assert e.kind == DnsEventKind.QUERY
    assert e.src_ip == "10.0.1.42"
    assert e.resolver_endpoint == "vpc-abc123"
    assert e.answers == ()
    assert e.unmapped["account_id"] == "123456789012"
    assert e.unmapped["region"] == "us-east-1"


@pytest.mark.asyncio
async def test_read_dns_logs_route53_response_with_answers(tmp_path: Path) -> None:
    log = tmp_path / "r53.log"
    line = _route53_line(
        qname="example.com.",
        answers=[{"Rdata": "93.184.216.34", "Type": "A", "Class": "IN"}],
    )
    log.write_text(line + "\n")

    out = await read_dns_logs(path=log)
    assert len(out) == 1
    e = out[0]
    assert e.kind == DnsEventKind.RESPONSE
    assert e.query_name == "example.com"
    assert e.answers == ("93.184.216.34",)


@pytest.mark.asyncio
async def test_read_dns_logs_route53_skips_malformed_lines(tmp_path: Path) -> None:
    log = tmp_path / "r53.log"
    log.write_text(
        "\n".join(
            [
                _route53_line(qname="ok.example."),
                "not json",
                "[1, 2, 3]",
                _route53_line(qname="ok2.example."),
            ]
        )
        + "\n"
    )

    out = await read_dns_logs(path=log)
    assert [e.query_name for e in out] == ["ok.example", "ok2.example"]


# ---------------------------- format dispatch ----------------------------


@pytest.mark.asyncio
async def test_format_dispatch_first_line_json_picks_route53(tmp_path: Path) -> None:
    """If the first non-blank line parses as JSON, the file is Route 53 format —
    even if a stray BIND-style line appears later (it gets dropped).
    """
    log = tmp_path / "mixed.log"
    log.write_text(_route53_line() + "\n" + _bind_line() + "\n")

    out = await read_dns_logs(path=log)
    # Only the Route 53 record parses; the BIND line is dropped by Route 53 parser.
    assert len(out) == 1
    # And the parsed record's source_ip comes from Route 53's srcaddr, not BIND src_ip.
    assert out[0].src_ip == "10.0.1.42"


@pytest.mark.asyncio
async def test_format_dispatch_first_line_text_picks_bind(tmp_path: Path) -> None:
    log = tmp_path / "mixed.log"
    log.write_text(_bind_line() + "\n" + _route53_line() + "\n")

    out = await read_dns_logs(path=log)
    # Only the BIND line parses; Route 53 JSON is not a BIND-shape line.
    assert len(out) == 1


@pytest.mark.asyncio
async def test_empty_file_returns_empty_tuple(tmp_path: Path) -> None:
    log = tmp_path / "empty.log"
    log.write_text("")
    out = await read_dns_logs(path=log)
    assert out == ()


@pytest.mark.asyncio
async def test_blank_lines_only(tmp_path: Path) -> None:
    log = tmp_path / "blanks.log"
    log.write_text("\n\n\n")
    out = await read_dns_logs(path=log)
    assert out == ()


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DnsLogReaderError, match="not found"):
        await read_dns_logs(path=tmp_path / "missing.log")


@pytest.mark.asyncio
async def test_path_is_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(DnsLogReaderError, match="not a file"):
        await read_dns_logs(path=tmp_path)
