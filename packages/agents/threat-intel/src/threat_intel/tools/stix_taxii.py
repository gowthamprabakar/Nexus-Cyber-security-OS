"""STIX 2.1 deserializer + TAXII 2.1 client (D.8 v0.2 Task 3).

The canonical CTI path (Q7): parse STIX 2.1 bundles/envelopes into typed objects and
poll TAXII 2.1 collections. The TAXII client runs over an **injectable transport**
(a small async `get` seam) so subscription + pagination + reconnect are unit-testable
without a live server — the httpx-backed transport is supplied by the caller (Task 4 /
the live feeds).

Resilience (WI-T9): transport hiccups retry with backoff (reconnect-on-failure); each
poll returns a **cursor** (the latest object `modified` time) for persistent resume.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol

#: STIX 2.1 SDO/SRO types relevant to threat-intel correlation.
RELEVANT_STIX_TYPES = frozenset(
    {
        "indicator",
        "malware",
        "attack-pattern",
        "intrusion-set",
        "threat-actor",
        "tool",
        "campaign",
        "relationship",
    }
)


class StixParseError(RuntimeError):
    """The payload is not a valid STIX 2.1 bundle."""


class TaxiiError(RuntimeError):
    """A TAXII 2.1 request failed (HTTP error or unreachable after retries)."""


@dataclass(frozen=True, slots=True)
class StixObject:
    id: str
    type: str
    raw: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.raw.get("name", ""))

    @property
    def modified(self) -> str:
        return str(self.raw.get("modified", self.raw.get("created", "")))


def parse_stix_objects(
    raw_objects: list[dict[str, Any]], *, only_relevant: bool = True
) -> list[StixObject]:
    """Parse a list of raw STIX objects → typed `StixObject`s, skipping malformed
    entries and (by default) types outside `RELEVANT_STIX_TYPES`."""
    out: list[StixObject] = []
    for obj in raw_objects:
        otype = str(obj.get("type", ""))
        oid = str(obj.get("id", ""))
        if not otype or not oid:
            continue
        if only_relevant and otype not in RELEVANT_STIX_TYPES:
            continue
        out.append(StixObject(id=oid, type=otype, raw=dict(obj)))
    return out


def parse_stix_bundle(bundle: dict[str, Any], *, only_relevant: bool = True) -> list[StixObject]:
    """Validate + parse a STIX 2.1 ``bundle`` object into typed objects."""
    if bundle.get("type") != "bundle":
        raise StixParseError(f"not a STIX bundle: type={bundle.get('type')!r}")
    return parse_stix_objects(bundle.get("objects", []), only_relevant=only_relevant)


@dataclass(frozen=True, slots=True)
class TaxiiCollection:
    id: str
    title: str
    can_read: bool


class TaxiiTransport(Protocol):
    """The async HTTP seam a `TaxiiClient` reads through. Returns ``(status, json)``."""

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]: ...


class TaxiiClient:
    """A minimal TAXII 2.1 reader: collection discovery + paged object polling with
    cursor tracking and reconnect-on-failure (WI-T9)."""

    _MEDIA = "application/taxii+json;version=2.1"

    def __init__(
        self, transport: TaxiiTransport, *, max_retries: int = 3, backoff_base: float = 0.0
    ) -> None:
        self._t = transport
        self._max_retries = max_retries
        self._backoff = backoff_base

    async def _get(self, url: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"Accept": self._MEDIA}
        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                status, body = await self._t.get(url, params=params, headers=headers)
                if status >= 400:
                    raise TaxiiError(f"TAXII {url} returned HTTP {status}")
                return body
            except TaxiiError:
                raise
            except Exception as exc:  # transport hiccup → reconnect (WI-T9)
                last_exc = exc
                if self._backoff:
                    await asyncio.sleep(self._backoff * (attempt + 1))
        raise TaxiiError(
            f"TAXII {url} unreachable after {self._max_retries} attempts"
        ) from last_exc

    async def collections(self, api_root_url: str) -> list[TaxiiCollection]:
        body = await self._get(api_root_url.rstrip("/") + "/collections/")
        return [
            TaxiiCollection(
                id=str(c["id"]),
                title=str(c.get("title", "")),
                can_read=bool(c.get("can_read", False)),
            )
            for c in body.get("collections", [])
        ]

    async def poll_collection(
        self, collection_url: str, *, added_after: str | None = None
    ) -> tuple[list[StixObject], str | None]:
        """Poll a collection's objects, following TAXII pagination (``more`` / ``next``).

        Returns ``(objects, cursor)`` where ``cursor`` is the latest object ``modified``
        time (for persistent resume). ``added_after`` resumes from a saved cursor.
        """
        objects: list[StixObject] = []
        url = collection_url.rstrip("/") + "/objects/"
        params: dict[str, str] = {}
        if added_after:
            params["added_after"] = added_after
        cursor = added_after
        while True:
            body = await self._get(url, params=params or None)
            page = parse_stix_objects(body.get("objects", []), only_relevant=True)
            objects.extend(page)
            for obj in page:
                if obj.modified and (cursor is None or obj.modified > cursor):
                    cursor = obj.modified
            if not body.get("more") or not body.get("next"):
                break
            params = {"next": str(body["next"])}
        return objects, cursor


def extract_actor_map(objects: list[StixObject]) -> dict[str, tuple[str, str]]:
    """Build a map of indicator_id → (actor_id, actor_name) from a parsed STIX bundle.

    Scans intrusion-set objects and relationship objects whose
    ``relationship_type`` is in ``{"indicates", "uses", "attributed-to"}`` and
    that link an intrusion-set to an indicator (in either direction).  Also
    falls back to an indicator's ``created_by_ref`` field if it points to an
    intrusion-set.

    Production actor-population is **operator-feed-dependent**: MITRE ATT&CK
    is TTP-focused, not IP→actor; real attributed IP IOCs come from a
    STIX/TAXII feed the operator wires.  This function is exercised offline via
    a STIX fixture (intrusion-set + indicator + "indicates" relationship).

    Returns a dict keyed by indicator STIX id, value = (actor_id, actor_name).
    """
    # Index intrusion-set objects by their STIX id.
    actor_by_id: dict[str, tuple[str, str]] = {}
    for obj in objects:
        if obj.type in {"intrusion-set", "threat-actor"}:
            actor_by_id[obj.id] = (obj.id, obj.name)

    _ATTRIBUTION_RELS = frozenset({"indicates", "uses", "attributed-to"})
    result: dict[str, tuple[str, str]] = {}

    for obj in objects:
        if obj.type == "relationship":
            rel_type = str(obj.raw.get("relationship_type", ""))
            if rel_type not in _ATTRIBUTION_RELS:
                continue
            src = str(obj.raw.get("source_ref", ""))
            tgt = str(obj.raw.get("target_ref", ""))
            # Relationship: intrusion-set --indicates/uses/attributed-to--> indicator
            if src in actor_by_id and tgt.startswith("indicator--"):
                result.setdefault(tgt, actor_by_id[src])
            # Relationship: indicator --attributed-to--> intrusion-set
            elif tgt in actor_by_id and src.startswith("indicator--"):
                result.setdefault(src, actor_by_id[tgt])

    # Fallback: indicator's created_by_ref → intrusion-set
    for obj in objects:
        if obj.type == "indicator" and obj.id not in result:
            cbr = str(obj.raw.get("created_by_ref", ""))
            if cbr in actor_by_id:
                result[obj.id] = actor_by_id[cbr]

    return result
