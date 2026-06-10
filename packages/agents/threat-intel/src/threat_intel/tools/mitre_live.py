"""Live MITRE ATT&CK STIX feed via TAXII 2.1 — continuous mode (D.8 v0.2 Task 7).

The v0.2 live counterpart to the offline ``read_mitre_attack`` (which stays for the
deterministic eval, WI-T5). Subscribes to the MITRE ATT&CK Enterprise TAXII 2.1
collection and parses each ``attack-pattern`` STIX object into a ``TechniqueRecord``
via the **shared offline parser** (byte-identical). Cursor + reconnect come from the
Task-3 `TaxiiClient`.

**Licence (H4 / WI maintained).** MITRE ATT&CK is CC-BY-4.0; the summarizer emits the
fixed attribution string. This live reader only ingests technique metadata; attribution
is unchanged from v0.1.
"""

from __future__ import annotations

import httpx

from threat_intel.tools.mitre_attack import TechniqueRecord, _try_parse
from threat_intel.tools.stix_taxii import TaxiiClient, TaxiiTransport

#: MITRE ATT&CK Enterprise TAXII 2.1 collection URL (operator-confirmed in the runbook).
MITRE_ENTERPRISE_COLLECTION_URL = (
    "https://attack-taxii.mitre.org/api/v21/collections/"
    "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
)


class MitreAttackLiveReader:
    """Polls a MITRE ATT&CK TAXII collection, parsing ``attack-pattern`` objects into
    TechniqueRecords via the shared offline parser. The `TaxiiClient` (and its injected
    transport) make this unit-testable without a live server."""

    __slots__ = ("_collection_url", "_taxii")

    def __init__(
        self, taxii: TaxiiClient, *, collection_url: str = MITRE_ENTERPRISE_COLLECTION_URL
    ) -> None:
        self._taxii = taxii
        self._collection_url = collection_url

    async def poll(
        self, *, since: str | None = None
    ) -> tuple[tuple[TechniqueRecord, ...], str | None]:
        """One TAXII poll. Returns ``(techniques, cursor)``; ``since`` resumes from a
        saved cursor (the latest object ``modified``)."""
        objects, cursor = await self._taxii.poll_collection(self._collection_url, added_after=since)
        techniques = tuple(t for t in (_try_parse(o.raw) for o in objects) if t is not None)
        return techniques, cursor


class _TaxiiHttpxTransport:
    """A `TaxiiTransport` over httpx (returns ``(status, json)``)."""

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            body: dict[str, object] = resp.json() if resp.status_code < 400 else {}
            return resp.status_code, body


def _taxii_transport() -> TaxiiTransport:
    return _TaxiiHttpxTransport()


async def read_mitre_attack_live(
    *, since: str | None = None
) -> tuple[tuple[TechniqueRecord, ...], str | None]:
    """Charter-registered live MITRE ATT&CK reader (continuous mode). The continuous
    ingestor calls this per cycle via ``ctx.call_tool`` for charter budget + audit."""
    reader = MitreAttackLiveReader(TaxiiClient(_taxii_transport()))
    return await reader.poll(since=since)
