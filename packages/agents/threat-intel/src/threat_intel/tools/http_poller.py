"""HTTP polling fallback for non-TAXII feeds (D.8 v0.2 Task 4).

For feeds without STIX/TAXII (abuse.ch URLhaus / ThreatFox, …) per Q7: poll a URL with
**ETag / Last-Modified conditional GETs** (skip unchanged payloads), **exponential-
backoff retry** on transport hiccups (WI-T9), and a **per-feed minimum poll interval**
(rate-limit respect). Runs over an injectable transport seam so it's unit-testable
without live HTTP; the httpx-backed transport is supplied by the live feeds.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol


class HttpPollError(RuntimeError):
    """A poll failed (HTTP >= 400, or unreachable after retries)."""


class HttpTransport(Protocol):
    """The async HTTP seam a poller reads through — returns ``(status, headers, body)``."""

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]: ...


@dataclass(frozen=True, slots=True)
class PollState:
    """Persistent per-feed cache state for conditional GETs (persist between polls)."""

    etag: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True, slots=True)
class PollResult:
    changed: bool  # False on 304 Not Modified
    status: int
    body: Any | None
    state: PollState  # updated etag / last_modified to persist for the next poll


def _header(headers: dict[str, str], name: str, default: str | None) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return default


class RateLimiter:
    """A per-feed minimum-interval gate. Pure + clock-injected for deterministic tests."""

    __slots__ = ("min_interval_sec",)

    def __init__(self, min_interval_sec: float) -> None:
        self.min_interval_sec = min_interval_sec

    def due(self, last_poll_ts: float | None, now_ts: float) -> bool:
        """True iff a poll is allowed now (first poll, or the interval has elapsed)."""
        if last_poll_ts is None:
            return True
        return (now_ts - last_poll_ts) >= self.min_interval_sec


class HttpPoller:
    """Polls a feed URL with conditional GETs + exponential-backoff retry."""

    def __init__(
        self, transport: HttpTransport, *, max_retries: int = 3, backoff_base: float = 0.0
    ) -> None:
        self._t = transport
        self._max_retries = max_retries
        self._backoff = backoff_base

    async def poll(self, url: str, *, state: PollState | None = None) -> PollResult:
        state = state or PollState()
        headers: dict[str, str] = {}
        if state.etag:
            headers["If-None-Match"] = state.etag
        if state.last_modified:
            headers["If-Modified-Since"] = state.last_modified

        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                status, resp_headers, body = await self._t.get(url, headers=headers or None)
            except Exception as exc:  # transport hiccup → backoff + retry (WI-T9)
                last_exc = exc
                if self._backoff:
                    await asyncio.sleep(self._backoff * (2**attempt))
                continue

            if status == 304:
                return PollResult(changed=False, status=304, body=None, state=state)
            if status >= 400:
                raise HttpPollError(f"{url} returned HTTP {status}")

            new_state = PollState(
                etag=_header(resp_headers, "ETag", state.etag),
                last_modified=_header(resp_headers, "Last-Modified", state.last_modified),
            )
            return PollResult(changed=True, status=status, body=body, state=new_state)

        raise HttpPollError(f"{url} unreachable after {self._max_retries} attempts") from last_exc
