"""D.8 v0.2 Task 6 — live CISA KEV catalog tests (injected transport; no live HTTP)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.tools.cisa_kev import CisaKevReaderError
from threat_intel.tools.kev_live import CisaKevLiveReader


def _kev(cve_id: str, date_added: str) -> dict[str, Any]:
    return {
        "cveID": cve_id,
        "vendorProject": "Acme",
        "product": "Widget",
        "vulnerabilityName": "RCE",
        "dateAdded": date_added,
        "shortDescription": "bad",
        "requiredAction": "patch",
        "knownRansomwareCampaignUse": "Known",
    }


class _FakeHttp:
    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body
        self.calls: list[str] = []

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        self.calls.append(url)
        return self._status, {}, self._body


@pytest.mark.asyncio
async def test_poll_parses_entries() -> None:
    body = {"vulnerabilities": [_kev("CVE-2026-0001", "2026-06-10")]}
    entries, cursor = await CisaKevLiveReader(_FakeHttp(200, body)).poll()
    assert [e.cve_id for e in entries] == ["CVE-2026-0001"]
    assert entries[0].known_ransomware_campaign_use is True
    assert cursor == "2026-06-10"


@pytest.mark.asyncio
async def test_dedup_filters_old_entries() -> None:
    body = {
        "vulnerabilities": [
            _kev("CVE-2026-0001", "2026-06-01"),  # old → dropped
            _kev("CVE-2026-0002", "2026-06-10"),  # new → kept
        ]
    }
    entries, cursor = await CisaKevLiveReader(_FakeHttp(200, body)).poll(since="2026-06-05")
    assert [e.cve_id for e in entries] == ["CVE-2026-0002"]
    assert cursor == "2026-06-10"


@pytest.mark.asyncio
async def test_empty_catalog_returns_cursor_unchanged() -> None:
    entries, cursor = await CisaKevLiveReader(_FakeHttp(200, {"vulnerabilities": []})).poll(
        since="2026-06-05"
    )
    assert entries == () and cursor == "2026-06-05"


@pytest.mark.asyncio
async def test_http_error_raises() -> None:
    with pytest.raises(CisaKevReaderError, match="HTTP 500"):
        await CisaKevLiveReader(_FakeHttp(500, None)).poll()


@pytest.mark.asyncio
async def test_polls_the_kev_url() -> None:
    t = _FakeHttp(200, {"vulnerabilities": []})
    await CisaKevLiveReader(t).poll()
    assert t.calls[0].endswith("known_exploited_vulnerabilities.json")


def test_read_cisa_kev_live_is_charter_registered() -> None:
    from threat_intel.agent import build_registry

    assert "read_cisa_kev_live" in build_registry().known_tools()
