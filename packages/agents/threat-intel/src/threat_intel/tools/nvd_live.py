"""Live NVD CVE feed — continuous mode (D.8 v0.2 Task 5).

The v0.2 live counterpart to the offline ``read_nvd_feed`` (which stays for the
deterministic eval, WI-T5). Polls the live NVD CVE 2.0 REST API and parses each
record with the **shared offline normalizer** (`nvd_feed._extract_vulnerabilities`
+ `_try_parse`) so live records are byte-identical in shape to the file path. Dedups
by a persistent ``lastModified`` cursor, and runs over an injectable transport seam
so it's unit-testable without live HTTP.

`NVD_API_KEY` (if set) rides in the ``apiKey`` request header and is **never logged**
(WI-T8); the reader keeps no secret on a repr-able field.
"""

from __future__ import annotations

import os
from urllib.parse import urlencode

from threat_intel.tools.http_poller import HttpTransport
from threat_intel.tools.nvd_feed import (
    NvdCveRecord,
    NvdFeedReaderError,
    _extract_vulnerabilities,
    _try_parse,
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_records(body: object) -> tuple[NvdCveRecord, ...]:
    raws = _extract_vulnerabilities(body)
    return tuple(r for r in (_try_parse(x) for x in raws) if r is not None)


class NvdLiveReader:
    """Polls the live NVD CVE 2.0 API, parses with the shared normalizer, dedups by a
    ``lastModified`` cursor. Transport is injected (fake in tests, httpx in prod)."""

    __slots__ = ("_t", "_url")  # no api-key field — it is read per-call, never stored

    def __init__(self, transport: HttpTransport, *, url: str = NVD_API_URL) -> None:
        self._t = transport
        self._url = url

    async def poll(
        self, *, since: str | None = None, api_key: str | None = None
    ) -> tuple[tuple[NvdCveRecord, ...], str | None]:
        """One live poll. Returns ``(new_records, cursor)`` where ``cursor`` is the
        latest ``lastModified`` (ISO) for persistent resume; ``since`` filters out
        already-seen records (dedup)."""
        params: dict[str, str] = {}
        if since:
            params["lastModStartDate"] = since
        url = self._url + (("?" + urlencode(params)) if params else "")
        headers = {"apiKey": api_key} if api_key else None

        status, _resp_headers, body = await self._t.get(url, headers=headers)
        if status >= 400:
            raise NvdFeedReaderError(f"NVD API returned HTTP {status}")

        records = _parse_records(body)
        if since is not None:
            records = tuple(r for r in records if r.last_modified.isoformat() > since)
        cursor = max((r.last_modified.isoformat() for r in records), default=since)
        return records, cursor


def _httpx_transport() -> HttpTransport:
    class _Httpx:
        async def get(
            self, url: str, *, headers: dict[str, str] | None = None
        ) -> tuple[int, dict[str, str], object]:
            import httpx

            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(url, headers=headers)
                body: object = resp.json() if resp.status_code < 400 else None
                return resp.status_code, dict(resp.headers), body

    return _Httpx()


async def read_nvd_live(*, since: str | None = None) -> tuple[tuple[NvdCveRecord, ...], str | None]:
    """Charter-registered live NVD reader (continuous mode). Builds the httpx transport,
    reads `NVD_API_KEY` from the environment (never logged), and returns
    ``(new_records, cursor)``. The continuous ingestor calls this per cycle via
    ``ctx.call_tool`` for charter budget + audit."""
    reader = NvdLiveReader(_httpx_transport())
    return await reader.poll(since=since, api_key=os.environ.get("NVD_API_KEY"))
