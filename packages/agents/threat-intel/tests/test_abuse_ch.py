"""D.8 v0.2 Task 8 — abuse.ch feeds (URLhaus + ThreatFox + MalwareBazaar) tests."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.schemas import IocType
from threat_intel.tools.abuse_ch import (
    AbuseChReaderError,
    read_malwarebazaar,
    read_threatfox,
    read_urlhaus,
)


class _FakeHttp:
    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        return self._status, {}, self._body


# ------------------------------- URLhaus ---------------------------------


@pytest.mark.asyncio
async def test_urlhaus_parses_url_iocs() -> None:
    body = {
        "urls": [
            {
                "url": "http://bad.example/x",
                "threat": "malware_download",
                "date_added": "2026-06-10 00:00:00",
            }
        ]
    }
    iocs = await read_urlhaus(transport=_FakeHttp(200, body))
    assert len(iocs) == 1
    assert iocs[0].ioc_type == IocType.URL
    assert iocs[0].value == "http://bad.example/x"
    assert iocs[0].threat == "malware_download" and iocs[0].source == "urlhaus"
    assert iocs[0].first_seen == "2026-06-10 00:00:00"


@pytest.mark.asyncio
async def test_urlhaus_skips_entries_without_url() -> None:
    iocs = await read_urlhaus(
        transport=_FakeHttp(200, {"urls": [{"threat": "x"}, {"url": "http://ok"}]})
    )
    assert [i.value for i in iocs] == ["http://ok"]


@pytest.mark.asyncio
async def test_urlhaus_empty() -> None:
    assert await read_urlhaus(transport=_FakeHttp(200, {"urls": []})) == ()


@pytest.mark.asyncio
async def test_urlhaus_http_error() -> None:
    with pytest.raises(AbuseChReaderError, match="HTTP 500"):
        await read_urlhaus(transport=_FakeHttp(500, None))


# ------------------------------- ThreatFox -------------------------------


@pytest.mark.asyncio
async def test_threatfox_maps_ioc_types() -> None:
    body = {
        "query_status": "ok",
        "data": [
            {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc"},
            {"ioc": "evil.example", "ioc_type": "domain", "threat_type": "botnet_cc"},
            {"ioc": "deadbeef" * 8, "ioc_type": "sha256_hash", "threat_type": "payload"},
        ],
    }
    iocs = await read_threatfox(transport=_FakeHttp(200, body))
    by_val = {i.value: i.ioc_type for i in iocs}
    assert by_val["1.2.3.4:443"] == IocType.IP
    assert by_val["evil.example"] == IocType.DOMAIN
    assert by_val["deadbeef" * 8] == IocType.FILE_HASH


@pytest.mark.asyncio
async def test_threatfox_skips_unknown_type() -> None:
    body = {"data": [{"ioc": "x", "ioc_type": "mutex"}, {"ioc": "1.2.3.4", "ioc_type": "ip"}]}
    iocs = await read_threatfox(transport=_FakeHttp(200, body))
    assert [i.value for i in iocs] == ["1.2.3.4"]  # mutex dropped (no internal mapping)


@pytest.mark.asyncio
async def test_threatfox_source_label() -> None:
    iocs = await read_threatfox(
        transport=_FakeHttp(200, {"data": [{"ioc": "x", "ioc_type": "url"}]})
    )
    assert iocs[0].source == "threatfox"


@pytest.mark.asyncio
async def test_threatfox_http_error() -> None:
    with pytest.raises(AbuseChReaderError):
        await read_threatfox(transport=_FakeHttp(403, None))


# ----------------------------- MalwareBazaar -----------------------------


@pytest.mark.asyncio
async def test_malwarebazaar_parses_hash_iocs() -> None:
    body = {
        "query_status": "ok",
        "data": [{"sha256_hash": "a" * 64, "signature": "Emotet", "first_seen": "2026-06-10"}],
    }
    iocs = await read_malwarebazaar(transport=_FakeHttp(200, body))
    assert len(iocs) == 1
    assert iocs[0].ioc_type == IocType.FILE_HASH and iocs[0].value == "a" * 64
    assert iocs[0].threat == "Emotet" and iocs[0].source == "malwarebazaar"


@pytest.mark.asyncio
async def test_malwarebazaar_skips_without_hash() -> None:
    iocs = await read_malwarebazaar(
        transport=_FakeHttp(200, {"data": [{"signature": "x"}, {"sha256_hash": "b" * 64}]})
    )
    assert [i.value for i in iocs] == ["b" * 64]


@pytest.mark.asyncio
async def test_malwarebazaar_http_error() -> None:
    with pytest.raises(AbuseChReaderError):
        await read_malwarebazaar(transport=_FakeHttp(500, None))


# ------------------------------ registration -----------------------------


def test_abuse_ch_feeds_charter_registered() -> None:
    from threat_intel.agent import build_registry

    known = build_registry().known_tools()
    assert {"read_urlhaus", "read_threatfox", "read_malwarebazaar"} <= set(known)
