"""Tests for correlation_id generator + asyncio-task-isolated contextvar."""

import asyncio

import pytest
from shared.fabric.correlation import (
    correlation_scope,
    current_correlation_id,
    new_correlation_id,
)


def test_new_correlation_id_is_unique() -> None:
    ids = {new_correlation_id() for _ in range(100)}
    assert len(ids) == 100


def test_new_correlation_id_is_lexically_sortable() -> None:
    """ULIDs are k-sortable: ids minted later sort >= ids minted earlier."""
    early = new_correlation_id()
    later = new_correlation_id()
    assert later >= early


def test_current_correlation_id_default_is_none() -> None:
    assert current_correlation_id() is None


def test_correlation_scope_sets_and_restores() -> None:
    cid = new_correlation_id()
    assert current_correlation_id() is None
    with correlation_scope(cid):
        assert current_correlation_id() == cid
    assert current_correlation_id() is None


def test_correlation_scope_nested_restores_parent() -> None:
    outer = new_correlation_id()
    inner = new_correlation_id()
    with correlation_scope(outer):
        assert current_correlation_id() == outer
        with correlation_scope(inner):
            assert current_correlation_id() == inner
        assert current_correlation_id() == outer


@pytest.mark.asyncio
async def test_correlation_id_is_isolated_per_asyncio_task() -> None:
    """Each asyncio.Task gets its own copy of the contextvar."""
    a_seen: list[str | None] = []
    b_seen: list[str | None] = []

    async def worker(cid: str, sink: list[str | None]) -> None:
        with correlation_scope(cid):
            await asyncio.sleep(0)  # yield to the other task
            sink.append(current_correlation_id())

    async with asyncio.TaskGroup() as tg:
        tg.create_task(worker("cid-A", a_seen))
        tg.create_task(worker("cid-B", b_seen))

    assert a_seen == ["cid-A"]
    assert b_seen == ["cid-B"]
