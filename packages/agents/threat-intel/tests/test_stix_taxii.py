"""D.8 v0.2 Task 3 — STIX 2.1 + TAXII 2.1 tests (injected transport; no live server)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.tools.stix_taxii import (
    StixParseError,
    TaxiiClient,
    TaxiiError,
    parse_stix_bundle,
    parse_stix_objects,
)

_IND = {
    "type": "indicator",
    "id": "indicator--1",
    "name": "bad-ip",
    "modified": "2026-06-10T00:00:00Z",
}
_MAL = {"type": "malware", "id": "malware--2", "name": "Emotet", "modified": "2026-06-11T00:00:00Z"}
_NOTE = {"type": "note", "id": "note--3", "content": "irrelevant"}


# ---------------------------- STIX parsing -------------------------------


def test_parse_bundle_returns_relevant_objects() -> None:
    objs = parse_stix_bundle({"type": "bundle", "objects": [_IND, _MAL, _NOTE]})
    assert {o.type for o in objs} == {"indicator", "malware"}  # note filtered out
    assert {o.id for o in objs} == {"indicator--1", "malware--2"}


def test_parse_bundle_non_bundle_raises() -> None:
    with pytest.raises(StixParseError, match="not a STIX bundle"):
        parse_stix_bundle({"type": "indicator", "objects": []})


def test_only_relevant_false_keeps_all() -> None:
    objs = parse_stix_objects([_IND, _NOTE], only_relevant=False)
    assert {o.type for o in objs} == {"indicator", "note"}


def test_malformed_objects_skipped() -> None:
    objs = parse_stix_objects([{"type": "indicator"}, {"id": "x--1"}, _IND])
    assert [o.id for o in objs] == ["indicator--1"]  # the two malformed dropped


def test_stix_object_properties() -> None:
    [obj] = parse_stix_objects([_MAL])
    assert obj.name == "Emotet"
    assert obj.modified == "2026-06-11T00:00:00Z"


# ---------------------------- TAXII client -------------------------------


class _FakeTransport:
    """Maps (url) → list of (status, body) responses, popped in order per url."""

    def __init__(self, routes: dict[str, list[tuple[int, dict[str, Any]]]]) -> None:
        self._routes = {k: list(v) for k, v in routes.items()}
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        self.calls.append((url, params))
        queue = self._routes.get(url)
        if not queue:
            return 404, {}
        return queue.pop(0) if len(queue) > 1 else queue[0]


@pytest.mark.asyncio
async def test_collections_parsed() -> None:
    t = _FakeTransport(
        {
            "https://taxii/api/collections/": [
                (200, {"collections": [{"id": "c1", "title": "ATT&CK", "can_read": True}]})
            ]
        }
    )
    cols = await TaxiiClient(t).collections("https://taxii/api")
    assert len(cols) == 1
    assert cols[0].id == "c1" and cols[0].can_read is True


@pytest.mark.asyncio
async def test_poll_single_page_with_cursor() -> None:
    t = _FakeTransport(
        {
            "https://taxii/api/collections/c1/objects/": [
                (200, {"objects": [_IND, _MAL], "more": False})
            ]
        }
    )
    objs, cursor = await TaxiiClient(t).poll_collection("https://taxii/api/collections/c1")
    assert {o.id for o in objs} == {"indicator--1", "malware--2"}
    assert cursor == "2026-06-11T00:00:00Z"  # the max modified time


@pytest.mark.asyncio
async def test_poll_follows_pagination() -> None:
    url = "https://taxii/api/collections/c1/objects/"
    t = _FakeTransport(
        {
            url: [
                (200, {"objects": [_IND], "more": True, "next": "page2"}),
                (200, {"objects": [_MAL], "more": False}),
            ]
        }
    )
    objs, _ = await TaxiiClient(t).poll_collection("https://taxii/api/collections/c1")
    assert {o.id for o in objs} == {"indicator--1", "malware--2"}  # both pages
    assert any(p == {"next": "page2"} for _, p in t.calls)  # the next token was sent


@pytest.mark.asyncio
async def test_poll_resumes_from_added_after() -> None:
    url = "https://taxii/api/collections/c1/objects/"
    t = _FakeTransport({url: [(200, {"objects": [_MAL], "more": False})]})
    await TaxiiClient(t).poll_collection(
        "https://taxii/api/collections/c1", added_after="2026-06-10T12:00:00Z"
    )
    assert t.calls[0][1] == {"added_after": "2026-06-10T12:00:00Z"}


@pytest.mark.asyncio
async def test_http_error_raises_taxii_error() -> None:
    t = _FakeTransport({"https://taxii/api/collections/": [(403, {})]})
    with pytest.raises(TaxiiError, match="HTTP 403"):
        await TaxiiClient(t).collections("https://taxii/api")


@pytest.mark.asyncio
async def test_transport_hiccup_reconnects() -> None:
    calls = {"n": 0}

    class _Flaky:
        async def get(self, url: str, **_: Any) -> tuple[int, dict[str, Any]]:
            calls["n"] += 1
            if calls["n"] < 2:
                raise ConnectionError("dropped")
            return 200, {"collections": []}

    cols = await TaxiiClient(_Flaky(), max_retries=3).collections("https://taxii/api")
    assert cols == [] and calls["n"] == 2  # retried once, then succeeded


@pytest.mark.asyncio
async def test_transport_unreachable_after_retries() -> None:
    class _Dead:
        async def get(self, url: str, **_: Any) -> tuple[int, dict[str, Any]]:
            raise ConnectionError("dropped")

    with pytest.raises(TaxiiError, match="unreachable after 3 attempts"):
        await TaxiiClient(_Dead(), max_retries=3).collections("https://taxii/api")
