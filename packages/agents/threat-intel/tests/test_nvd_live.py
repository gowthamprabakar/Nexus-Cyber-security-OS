"""D.8 v0.2 Task 5 — live NVD CVE feed tests (injected transport; no live HTTP)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.tools.nvd_feed import NvdFeedReaderError
from threat_intel.tools.nvd_live import NvdLiveReader


def _cve(cve_id: str, last_modified: str) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-06-01T00:00:00.000",
            "lastModified": last_modified,
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "test cve"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
            },
            "references": [{"url": "https://example/x"}],
        }
    }


class _FakeHttp:
    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        self.calls.append((url, headers))
        return self._status, {}, self._body


@pytest.mark.asyncio
async def test_poll_parses_records_via_shared_normalizer() -> None:
    body = {"vulnerabilities": [_cve("CVE-2026-0001", "2026-06-10T00:00:00.000")]}
    recs, cursor = await NvdLiveReader(_FakeHttp(200, body)).poll()
    assert [r.cve_id for r in recs] == ["CVE-2026-0001"]
    assert recs[0].cvss_v3_severity == "CRITICAL" and recs[0].cvss_v3_score == 9.8
    assert cursor == "2026-06-10T00:00:00"


@pytest.mark.asyncio
async def test_dedup_filters_records_at_or_before_cursor() -> None:
    body = {
        "vulnerabilities": [
            _cve("CVE-2026-0001", "2026-06-01T00:00:00.000"),  # old → dropped
            _cve("CVE-2026-0002", "2026-06-10T00:00:00.000"),  # new → kept
        ]
    }
    recs, cursor = await NvdLiveReader(_FakeHttp(200, body)).poll(since="2026-06-05T00:00:00")
    assert [r.cve_id for r in recs] == ["CVE-2026-0002"]
    assert cursor == "2026-06-10T00:00:00"


@pytest.mark.asyncio
async def test_since_passed_as_lastmodstartdate_param() -> None:
    t = _FakeHttp(200, {"vulnerabilities": []})
    await NvdLiveReader(t).poll(since="2026-06-05T00:00:00")
    assert "lastModStartDate=2026-06-05" in t.calls[0][0]


@pytest.mark.asyncio
async def test_api_key_rides_in_header() -> None:
    t = _FakeHttp(200, {"vulnerabilities": []})
    await NvdLiveReader(t).poll(api_key="SECRET-KEY")
    assert t.calls[0][1] == {"apiKey": "SECRET-KEY"}


@pytest.mark.asyncio
async def test_no_api_key_sends_no_header() -> None:
    t = _FakeHttp(200, {"vulnerabilities": []})
    await NvdLiveReader(t).poll()
    assert t.calls[0][1] is None


def test_reader_keeps_no_api_key_field() -> None:
    # WI-T8: the api key is read per-call, never stored on a repr-able field.
    assert set(NvdLiveReader.__slots__) == {"_t", "_url"}


@pytest.mark.asyncio
async def test_http_error_raises() -> None:
    with pytest.raises(NvdFeedReaderError, match="HTTP 503"):
        await NvdLiveReader(_FakeHttp(503, None)).poll()


def test_read_nvd_live_is_charter_registered() -> None:
    from threat_intel.agent import build_registry

    assert "read_nvd_live" in build_registry().known_tools()
