"""supervisor v0.2 Task 6 — dynamic concurrency config tests (Q2)."""

from __future__ import annotations

import asyncio

import pytest
from supervisor.concurrency.config import (
    ConcurrencyConfig,
    SemaphoreWaitTimeout,
    acquire_within,
    build_semaphores,
    parse_concurrency_config,
)


def test_parse_defaults_when_absent() -> None:
    cfg = parse_concurrency_config(None)
    assert cfg.default_cap == 4 and cfg.overrides == {}


def test_parse_full_config() -> None:
    cfg = parse_concurrency_config({"default_cap": 8, "overrides": {"audit": 2}})
    assert cfg.default_cap == 8 and cfg.overrides == {"audit": 2}


def test_parse_rejects_bad_default() -> None:
    with pytest.raises(ValueError, match="default_cap"):
        parse_concurrency_config({"default_cap": 0})


def test_parse_rejects_bad_override() -> None:
    with pytest.raises(ValueError, match="override cap"):
        parse_concurrency_config({"overrides": {"audit": -1}})


def test_build_semaphores_applies_config() -> None:
    sems = build_semaphores(ConcurrencyConfig(default_cap=5, overrides={"audit": 1}))
    assert sems.cap_for("audit") == 1 and sems.cap_for("compliance") == 5


@pytest.mark.asyncio
async def test_acquire_within_succeeds() -> None:
    sems = build_semaphores(parse_concurrency_config({"overrides": {"audit": 1}}))
    async with acquire_within(sems, "audit", timeout_s=1.0):
        pass  # acquired + released cleanly


@pytest.mark.asyncio
async def test_acquire_within_times_out_under_backpressure() -> None:
    sems = build_semaphores(parse_concurrency_config({"overrides": {"audit": 1}}))
    # Hold the only slot, then a second acquire must time out.
    async with acquire_within(sems, "audit", timeout_s=1.0):
        with pytest.raises(SemaphoreWaitTimeout, match="could not acquire"):
            async with acquire_within(sems, "audit", timeout_s=0.05):
                pass


@pytest.mark.asyncio
async def test_slot_released_after_timeout_holder_exits() -> None:
    sems = build_semaphores(parse_concurrency_config({"overrides": {"audit": 1}}))
    async with acquire_within(sems, "audit", timeout_s=1.0):
        await asyncio.sleep(0)
    # Holder released -> a fresh acquire succeeds.
    async with acquire_within(sems, "audit", timeout_s=1.0):
        pass
