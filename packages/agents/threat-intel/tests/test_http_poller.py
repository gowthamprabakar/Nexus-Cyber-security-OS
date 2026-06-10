"""D.8 v0.2 Task 4 — HTTP polling fallback tests (injected transport; no live HTTP)."""

from __future__ import annotations

from typing import Any

import pytest
from threat_intel.tools.http_poller import (
    HttpPoller,
    HttpPollError,
    PollState,
    RateLimiter,
)


class _FakeHttp:
    """Returns queued (status, headers, body) responses; records sent headers."""

    def __init__(self, responses: list[tuple[int, dict[str, str], Any]]) -> None:
        self._responses = list(responses)
        self.sent_headers: list[dict[str, str] | None] = []

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        self.sent_headers.append(headers)
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


# ------------------------------- HttpPoller ------------------------------


@pytest.mark.asyncio
async def test_poll_200_returns_body_and_caches_validators() -> None:
    t = _FakeHttp(
        [(200, {"ETag": "abc", "Last-Modified": "Wed, 10 Jun 2026 00:00:00 GMT"}, {"x": 1})]
    )
    res = await HttpPoller(t).poll("https://urlhaus/feed")
    assert res.changed is True and res.status == 200 and res.body == {"x": 1}
    assert res.state.etag == "abc"
    assert res.state.last_modified == "Wed, 10 Jun 2026 00:00:00 GMT"


@pytest.mark.asyncio
async def test_conditional_headers_sent_from_state() -> None:
    t = _FakeHttp([(200, {}, [])])
    await HttpPoller(t).poll(
        "https://urlhaus/feed", state=PollState(etag="abc", last_modified="Wed")
    )
    assert t.sent_headers[0] == {"If-None-Match": "abc", "If-Modified-Since": "Wed"}


@pytest.mark.asyncio
async def test_304_not_modified_changed_false_state_preserved() -> None:
    t = _FakeHttp([(304, {}, None)])
    prior = PollState(etag="abc", last_modified="Wed")
    res = await HttpPoller(t).poll("https://urlhaus/feed", state=prior)
    assert res.changed is False and res.status == 304 and res.body is None
    assert res.state == prior  # unchanged — nothing to re-persist


@pytest.mark.asyncio
async def test_4xx_raises() -> None:
    t = _FakeHttp([(429, {}, None)])
    with pytest.raises(HttpPollError, match="HTTP 429"):
        await HttpPoller(t).poll("https://urlhaus/feed")


@pytest.mark.asyncio
async def test_transport_hiccup_then_success() -> None:
    calls = {"n": 0}

    class _Flaky:
        async def get(self, url: str, **_: Any) -> tuple[int, dict[str, str], Any]:
            calls["n"] += 1
            if calls["n"] < 2:
                raise ConnectionError("reset")
            return 200, {}, {"ok": True}

    res = await HttpPoller(_Flaky(), max_retries=3).poll("https://urlhaus/feed")
    assert res.changed is True and res.body == {"ok": True} and calls["n"] == 2


@pytest.mark.asyncio
async def test_transport_dead_raises_after_retries() -> None:
    class _Dead:
        async def get(self, url: str, **_: Any) -> tuple[int, dict[str, str], Any]:
            raise ConnectionError("reset")

    with pytest.raises(HttpPollError, match="unreachable after 3 attempts"):
        await HttpPoller(_Dead(), max_retries=3).poll("https://urlhaus/feed")


@pytest.mark.asyncio
async def test_etag_case_insensitive_header_read() -> None:
    t = _FakeHttp([(200, {"etag": "lower"}, {})])  # lowercase header name
    res = await HttpPoller(t).poll("https://urlhaus/feed")
    assert res.state.etag == "lower"


# ------------------------------- RateLimiter -----------------------------


def test_rate_limiter_first_poll_is_due() -> None:
    assert RateLimiter(60.0).due(last_poll_ts=None, now_ts=1000.0) is True


def test_rate_limiter_too_soon_not_due() -> None:
    assert RateLimiter(60.0).due(last_poll_ts=1000.0, now_ts=1030.0) is False


def test_rate_limiter_interval_elapsed_is_due() -> None:
    assert RateLimiter(60.0).due(last_poll_ts=1000.0, now_ts=1061.0) is True
