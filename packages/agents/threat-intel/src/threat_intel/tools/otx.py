"""AlienVault OTX live feed (D.8 v0.2 Task 9).

HTTP-polled (Q7) OTX subscribed-pulses feed, normalized to the internal `IocType`
vocabulary. The `OTX_API_KEY` (required) rides in the ``X-OTX-API-KEY`` header and is
**never stored on a repr-able field or logged** (WI-T8). Injectable transport → unit-
testable without live HTTP.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from threat_intel.schemas import IocType
from threat_intel.tools.http_poller import HttpTransport
from threat_intel.tools.nvd_live import _httpx_transport

OTX_SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

#: OTX indicator ``type`` → internal IocType.
_OTX_TYPE_MAP = {
    "IPv4": IocType.IP,
    "IPv6": IocType.IP,
    "domain": IocType.DOMAIN,
    "hostname": IocType.DOMAIN,
    "URL": IocType.URL,
    "URI": IocType.URL,
    "FileHash-SHA256": IocType.FILE_HASH,
    "FileHash-SHA1": IocType.FILE_HASH,
    "FileHash-MD5": IocType.FILE_HASH,
}


class OtxReaderError(RuntimeError):
    """An OTX request failed (HTTP error, or missing API key)."""


@dataclass(frozen=True, slots=True)
class OtxIndicator:
    ioc_type: IocType
    value: str
    pulse_name: str
    source: str = "otx"


def _normalize_pulses(body: object) -> tuple[OtxIndicator, ...]:
    if not isinstance(body, dict):
        return ()
    out: list[OtxIndicator] = []
    for pulse in body.get("results", []):
        if not isinstance(pulse, dict):
            continue
        name = str(pulse.get("name", ""))
        for ind in pulse.get("indicators", []):
            if not isinstance(ind, dict):
                continue
            value = ind.get("indicator")
            ioc_type = _OTX_TYPE_MAP.get(str(ind.get("type", "")))
            if not value or ioc_type is None:
                continue
            out.append(OtxIndicator(ioc_type=ioc_type, value=str(value), pulse_name=name))
    return tuple(out)


async def read_otx(
    *, transport: HttpTransport | None = None, api_key: str | None = None
) -> tuple[OtxIndicator, ...]:
    """Read OTX subscribed-pulse indicators → normalized IOCs.

    `api_key` defaults to the `OTX_API_KEY` env var (never logged). The continuous
    ingestor calls the charter-registered wrapper per cycle via ``ctx.call_tool``.
    """
    key = api_key if api_key is not None else os.environ.get("OTX_API_KEY")
    if not key:
        raise OtxReaderError("OTX_API_KEY is required for the OTX feed")
    t = transport or _httpx_transport()
    status, _headers, body = await t.get(OTX_SUBSCRIBED_URL, headers={"X-OTX-API-KEY": key})
    if status >= 400:
        raise OtxReaderError(f"OTX returned HTTP {status}")
    return _normalize_pulses(body)
