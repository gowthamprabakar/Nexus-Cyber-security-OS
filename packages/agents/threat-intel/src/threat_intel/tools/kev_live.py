"""Live CISA KEV catalog — continuous mode (D.8 v0.2 Task 6).

The v0.2 live counterpart to the offline ``read_cisa_kev`` (which stays for the
deterministic eval, WI-T5). Polls the live CISA Known Exploited Vulnerabilities JSON
and parses each entry with the **shared offline normalizer** so entries are
byte-identical in shape. Dedups by a persistent ``dateAdded`` cursor. The KEV catalog
is public (no credential). Injectable transport → unit-testable without live HTTP.
"""

from __future__ import annotations

from threat_intel.tools.cisa_kev import (
    CisaKevReaderError,
    KevEntry,
    _extract_vulnerabilities,
    _try_parse,
)
from threat_intel.tools.http_poller import HttpTransport
from threat_intel.tools.nvd_live import _httpx_transport

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_entries(body: object) -> tuple[KevEntry, ...]:
    raws = _extract_vulnerabilities(body)
    return tuple(e for e in (_try_parse(x) for x in raws) if e is not None)


class CisaKevLiveReader:
    """Polls the live CISA KEV catalog, parses with the shared normalizer, dedups by a
    ``dateAdded`` cursor. Transport is injected (fake in tests, httpx in prod)."""

    __slots__ = ("_t", "_url")

    def __init__(self, transport: HttpTransport, *, url: str = KEV_URL) -> None:
        self._t = transport
        self._url = url

    async def poll(self, *, since: str | None = None) -> tuple[tuple[KevEntry, ...], str | None]:
        """One live poll. Returns ``(new_entries, cursor)`` where ``cursor`` is the
        latest ``dateAdded`` (ISO date) for persistent resume; ``since`` filters out
        already-seen entries (dedup)."""
        status, _resp_headers, body = await self._t.get(self._url, headers=None)
        if status >= 400:
            raise CisaKevReaderError(f"CISA KEV returned HTTP {status}")

        entries = _parse_entries(body)
        if since is not None:
            entries = tuple(e for e in entries if e.date_added.isoformat() > since)
        cursor = max((e.date_added.isoformat() for e in entries), default=since)
        return entries, cursor


async def read_cisa_kev_live(
    *, since: str | None = None
) -> tuple[tuple[KevEntry, ...], str | None]:
    """Charter-registered live CISA KEV reader (continuous mode). The continuous ingestor
    calls this per cycle via ``ctx.call_tool`` for charter budget + audit."""
    return await CisaKevLiveReader(_httpx_transport()).poll(since=since)
