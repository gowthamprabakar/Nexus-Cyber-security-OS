"""D.8 v0.2 Task 9 — AlienVault OTX live feed tests (injected transport; no live HTTP)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.schemas import IocType
from threat_intel.tools.otx import OtxReaderError, read_otx


class _FakeHttp:
    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body
        self.headers_seen: list[dict[str, str] | None] = []

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        self.headers_seen.append(headers)
        return self._status, {}, self._body


_PULSES = {
    "results": [
        {
            "name": "APT-X campaign",
            "indicators": [
                {"indicator": "1.2.3.4", "type": "IPv4"},
                {"indicator": "evil.example", "type": "domain"},
                {"indicator": "a" * 64, "type": "FileHash-SHA256"},
                {"indicator": "skip-me", "type": "Mutex"},  # unmapped → dropped
            ],
        }
    ]
}


@pytest.mark.asyncio
async def test_normalizes_indicators_by_type() -> None:
    iocs = await read_otx(transport=_FakeHttp(200, _PULSES), api_key="K")
    by_val = {i.value: i.ioc_type for i in iocs}
    assert by_val == {
        "1.2.3.4": IocType.IP,
        "evil.example": IocType.DOMAIN,
        "a" * 64: IocType.FILE_HASH,
    }  # the Mutex indicator was dropped
    assert all(i.source == "otx" and i.pulse_name == "APT-X campaign" for i in iocs)


@pytest.mark.asyncio
async def test_api_key_rides_in_header() -> None:
    t = _FakeHttp(200, {"results": []})
    await read_otx(transport=t, api_key="SECRET-OTX")
    assert t.headers_seen[0] == {"X-OTX-API-KEY": "SECRET-OTX"}


@pytest.mark.asyncio
async def test_missing_api_key_raises() -> None:
    with pytest.raises(OtxReaderError, match="OTX_API_KEY is required"):
        await read_otx(transport=_FakeHttp(200, {"results": []}), api_key="")


@pytest.mark.asyncio
async def test_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTX_API_KEY", "env-key")
    t = _FakeHttp(200, {"results": []})
    await read_otx(transport=t)
    assert t.headers_seen[0] == {"X-OTX-API-KEY": "env-key"}


@pytest.mark.asyncio
async def test_http_error_raises() -> None:
    with pytest.raises(OtxReaderError, match="HTTP 401"):
        await read_otx(transport=_FakeHttp(401, None), api_key="K")


@pytest.mark.asyncio
async def test_empty_pulses() -> None:
    assert await read_otx(transport=_FakeHttp(200, {"results": []}), api_key="K") == ()


def test_read_otx_is_charter_registered() -> None:
    from threat_intel.agent import build_registry

    assert "read_otx" in build_registry().known_tools()
