"""Live integration tests for D.7's F.7 v0.2 bus_emit path.

**Skipped by default.** Enable with:

    NEXUS_LIVE_NATS=1 uv run pytest \\
        packages/agents/investigation/tests/integration/test_bus_emit_live.py -v

**Prerequisites:**

- A NATS server with JetStream enabled, reachable on the configured URL
  (default `nats://localhost:4222`). Same prerequisite shape as the F.7
  v0.1 Task 6 live lane. The canonical dev path is the `nats` service
  in [docker/docker-compose.dev.yml](../../../../../../docker/docker-compose.dev.yml)
  (landed in F.7 v0.1 Task 1):

      docker compose -f docker/docker-compose.dev.yml up -d nats

  A standalone `nats-server -js --store_dir <tmp>` binary works
  equivalently — JetStream protocol stable across 2.10/2.11/2.14.

**What this lane proves (and why it exists).**

F.7 v0.2 Tasks 1-3 ship the lifecycle-event schema, the
`--publish-events-to-bus` flag, the `BusEmitter` class, and the
agent-driver wiring + 24 mocked unit tests. Those prove the *contract*
— payload shape, audit-action vocabulary, non-fatal failure handling.
They do NOT prove the *integration* — that a real D.7 investigation
run with the flag ON actually causes a real subscriber on the real
broker to receive the lifecycle events with the right payload + the
right `Nexus-Correlation-Id` header.

This is the F.7 v0.2 equivalent of F.7 v0.1's Task 6 (which proved the
substrate end-to-end). Until this lane runs green, the D.7 migration's
end-to-end correctness is a hypothesis.

**The two live tests.**

1. `test_d7_publishes_started_and_completed_against_real_broker` — the
   happy-path proof. Subscribes test-side to
   `events.tenant.<test-tid>.investigation.>`; runs a real D.7
   investigation with `publish_events_to_bus=True`; waits up to 10s
   for delivery; asserts both `started` and `completed` events arrived
   with the right `investigation_id` + payload + `Nexus-Correlation-Id`
   header. Also asserts the 4 filesystem artifacts are still written
   (the additive proof — bus path added, filesystem path intact).
2. `test_d7_publishes_failed_against_real_broker_on_pipeline_exception`
   — the failure-path proof. Forces `_stage_spawn` to raise; runs
   D.7 with the flag on; asserts the `failed` event arrived with
   `stage="spawn"` + `error_class="RuntimeError"` + header + payload;
   asserts the original D.7 exception still propagates (D.7's failure
   semantics preserved).

Together these two tests prove all 3 lifecycle event types
(`started` / `completed` / `failed`) reach a real broker subscriber
end-to-end.

**Acceptance.** Both tests pass in a single `NEXUS_LIVE_NATS=1` run
against a real NATS broker. Skip-reason discipline: when
`NEXUS_LIVE_NATS != "1"`, the entire module SKIPs with a reason string
naming the env var + the canonical docker-compose command; when the
env var IS set but the broker isn't reachable, the module SKIPs with
a reason naming the missing pre-condition. The mocked lane (Task 3's
24 tests) stays green at all times.

**Permanent documented limitation carried forward from F.7 v0.1 §6.**
The brew-installed `nats-server` may be ahead of the `nats:2.10-alpine`
image pinned in the compose file (today, brew ships `v2.14.0` vs the
image's `v2.10.x`). The JetStream protocol surface this test exercises
is stable across 2.10/2.11/2.14. F.7 v0.2 added NO new NATS-version
dependency; the v0.1 §6 deviation note still applies and still requires
no production change.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from charter.memory.models import Base
from investigation.agent import run as investigation_run
from investigation.schemas import IncidentReport
from shared.fabric import (
    CORRELATION_ID_HEADER,
    EVENTS_STREAM,
    JetStreamClient,
)
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


_NATS_URL = os.environ.get("NEXUS_NATS_URL", "nats://localhost:4222")
_NATS_MON_HOST = "localhost"
_NATS_MON_PORT = 8222


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_NATS") == "1"


def _broker_reachable() -> tuple[bool, str]:
    """Pre-flight TCP probe of the NATS monitoring port (8222 / /healthz)."""
    try:
        with socket.create_connection((_NATS_MON_HOST, _NATS_MON_PORT), timeout=2.0):
            return True, ""
    except OSError as exc:
        return False, (
            f"NATS broker monitoring port {_NATS_MON_HOST}:{_NATS_MON_PORT} not reachable "
            f"({exc}); bring it up with `docker compose -f docker/docker-compose.dev.yml "
            f"up -d nats` or `nats-server -js --store_dir <tmp>`"
        )


_TOOLING_OK, _TOOLING_REASON = (
    (False, "live tests disabled") if not _live_enabled() else _broker_reachable()
)

pytestmark.append(
    pytest.mark.skipif(
        not _TOOLING_OK,
        reason=(
            f"set NEXUS_LIVE_NATS=1 + ensure a JetStream-enabled NATS broker is "
            f"reachable at {_NATS_URL} (monitoring on {_NATS_MON_HOST}:{_NATS_MON_PORT}); "
            f"current status: {_TOOLING_REASON}. See module docstring for setup."
        ),
    )
)


# ---------------------------- helpers + fixtures --------------------------


def _fresh_tenant_id() -> str:
    """Generate a per-test 26-char tenant ULID so the subscriber only sees this run's events."""
    return str(uuid.uuid4().hex[:26]).upper().ljust(26, "0")[:26]


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[Any]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(session_factory: async_sessionmaker[Any]) -> AuditStore:
    return AuditStore(session_factory)


@pytest_asyncio.fixture
async def semantic_store(session_factory: async_sessionmaker[Any]) -> SemanticStore:
    return SemanticStore(session_factory)


def _contract(workspace_root: Path, *, tenant_id: str) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=tenant_id,
        task="Investigate the incident (live bus test)",
        required_outputs=[
            "incident_report.json",
            "timeline.json",
            "hypotheses.md",
            "containment_plan.yaml",
        ],
        budget=BudgetSpec(
            llm_calls=30,
            tokens=60000,
            wall_clock_sec=600.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "audit_trail_query",
            "memory_neighbors_walk",
            "find_related_findings",
            "extract_iocs",
            "map_to_mitre",
            "reconstruct_timeline",
            "synthesize_hypotheses",
        ],
        completion_condition="incident_report.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


@pytest_asyncio.fixture
async def live_subscriber_client() -> AsyncIterator[JetStreamClient]:
    """A JetStreamClient connected to the live broker, used by tests as
    the test-side subscriber. Teardown closes the connection so the
    next test starts clean."""
    client = JetStreamClient(servers=[_NATS_URL])
    await client.connect()
    # Ensure all 5 ADR-004 streams exist (idempotent — fine if they do).
    await client.ensure_streams()
    try:
        yield client
    finally:
        await client.close()


async def _collect_messages(
    client: JetStreamClient,
    subject_filter: str,
    durable_name: str,
    *,
    expected_count: int,
    timeout_seconds: float = 10.0,
) -> list[Any]:
    """Subscribe + collect up to `expected_count` messages within
    `timeout_seconds`. Returns the captured messages in arrival order."""
    captured: list[Any] = []

    async def cb(msg: Any) -> None:
        captured.append(msg)
        await msg.ack()

    sub = await client.subscribe(
        EVENTS_STREAM,
        subject_filter,
        cb,
        durable_name=durable_name,
    )
    try:
        # Poll loop with 100ms granularity for snappy test wall-time.
        deadline = asyncio.get_event_loop().time() + timeout_seconds
        while len(captured) < expected_count and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.1)
        return captured
    finally:
        with contextlib.suppress(Exception):
            await sub.unsubscribe()


# ---------------------------- tests ---------------------------------------


async def test_d7_publishes_started_and_completed_against_real_broker(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    live_subscriber_client: JetStreamClient,
) -> None:
    """**LOAD-BEARING LIVE PROOF.** Run a real D.7 investigation with
    `publish_events_to_bus=True` against a real NATS broker; subscribe
    test-side to `events.tenant.<test-tid>.investigation.>`; receive both
    `started` and `completed` events; assert payload + header.

    Also asserts the 4 filesystem artifacts are still written — the
    additive proof that the bus path was added WITHOUT breaking D.7's
    existing filesystem-artifacts contract.
    """
    tenant_id = _fresh_tenant_id()
    subject_filter = f"events.tenant.{tenant_id}.investigation.>"
    durable_name = f"test-bus-emit-live-{tenant_id[:8].lower()}"

    # Subscribe first so we don't miss the events D.7 publishes.
    captured: list[Any] = []

    async def cb(msg: Any) -> None:
        captured.append(msg)
        await msg.ack()

    sub = await live_subscriber_client.subscribe(
        EVENTS_STREAM,
        subject_filter,
        cb,
        durable_name=durable_name,
    )

    try:
        # Run D.7 with the flag ON. Empty sources → quick path through
        # all 6 stages, both lifecycle events fire.
        contract = _contract(tmp_path, tenant_id=tenant_id)
        report = await investigation_run(
            contract,
            llm_provider=None,
            audit_store=audit_store,
            semantic_store=semantic_store,
            sibling_workspaces=(),
            since=None,
            until=None,
            publish_events_to_bus=True,
        )
        assert isinstance(report, IncidentReport)

        # Wait for both lifecycle events (started + completed).
        deadline = asyncio.get_event_loop().time() + 10.0
        while len(captured) < 2 and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.1)

        assert len(captured) == 2, (
            f"expected 2 lifecycle events on {subject_filter!r} within 10s; got "
            f"{len(captured)}: subjects={[m.subject for m in captured]!r}"
        )

        # Sort by event_type so the order assertion is deterministic.
        events_by_type: dict[str, Any] = {}
        for msg in captured:
            decoded = json.loads(msg.data)
            events_by_type[decoded["event_type"]] = (msg, decoded)
        assert set(events_by_type.keys()) == {"started", "completed"}

        # Per-event payload + header verification.
        for event_type, (msg, decoded) in events_by_type.items():
            assert msg.subject == (f"events.tenant.{tenant_id}.investigation.{event_type}"), (
                f"subject mismatch for {event_type}: {msg.subject!r}"
            )
            assert decoded["event_type"] == event_type
            assert decoded["tenant_id"] == tenant_id
            assert decoded["correlation_id"] == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
            assert len(decoded["investigation_id"]) == 26
            # Success-path payloads must NOT carry stage/error_class.
            assert "stage" not in decoded
            assert "error_class" not in decoded
            # The header round-trip — the load-bearing claim of v0.2 + v0.1.
            assert msg.headers is not None, (
                f"received {event_type} message has no headers — "
                "Nexus-Correlation-Id absent on the wire"
            )
            assert msg.headers.get(CORRELATION_ID_HEADER) == "01J7M3X9Z1K8RPVQNH2T8DBHFZ", (
                f"correlation_id header mismatch on {event_type}: headers={msg.headers!r}"
            )

        # Both events carry the same investigation_id (one D.7 run → one id).
        started_id = events_by_type["started"][1]["investigation_id"]
        completed_id = events_by_type["completed"][1]["investigation_id"]
        assert started_id == completed_id, (
            f"started+completed investigation_id mismatch: "
            f"started={started_id!r} completed={completed_id!r}"
        )

        # ADDITIVE PROOF: the 4 filesystem artifacts were also written.
        ws = Path(contract.workspace)
        assert (ws / "incident_report.json").is_file()
        assert (ws / "timeline.json").is_file()
        assert (ws / "hypotheses.md").is_file()
        assert (ws / "containment_plan.yaml").is_file()
    finally:
        with contextlib.suppress(Exception):
            await sub.unsubscribe()


async def test_d7_publishes_failed_against_real_broker_on_pipeline_exception(
    tmp_path: Path,
    semantic_store: SemanticStore,
    live_subscriber_client: JetStreamClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**LOAD-BEARING FAILED-EVENT LIVE PROOF.** Force `_stage_spawn` to
    raise; subscribe test-side; assert the `failed` event arrives with
    the right `stage` + `error_class` + payload + header; assert the
    original D.7 exception still propagates (D.7's existing failure
    semantics preserved).
    """
    import investigation.agent as agent_mod

    async def _explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError("synthetic spawn failure for live test")

    monkeypatch.setattr(agent_mod, "_stage_spawn", _explode)

    tenant_id = _fresh_tenant_id()
    subject_filter = f"events.tenant.{tenant_id}.investigation.>"
    durable_name = f"test-bus-emit-live-failed-{tenant_id[:8].lower()}"

    captured: list[Any] = []

    async def cb(msg: Any) -> None:
        captured.append(msg)
        await msg.ack()

    sub = await live_subscriber_client.subscribe(
        EVENTS_STREAM,
        subject_filter,
        cb,
        durable_name=durable_name,
    )

    # Need a fresh audit_store since the failed test monkeypatches the
    # spawn stage and we don't want fixture contamination.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    fresh_audit_store = AuditStore(async_sessionmaker(engine, expire_on_commit=False))

    try:
        contract = _contract(tmp_path, tenant_id=tenant_id)
        # Original D.7 exception MUST still propagate.
        with pytest.raises(RuntimeError, match="synthetic spawn failure"):
            await investigation_run(
                contract,
                llm_provider=None,
                audit_store=fresh_audit_store,
                semantic_store=semantic_store,
                sibling_workspaces=(),
                since=None,
                until=None,
                publish_events_to_bus=True,
            )

        # Wait for both started + failed events (started fires at Stage-1
        # entry before the forced spawn failure; failed fires from the
        # except path before the exception propagates).
        deadline = asyncio.get_event_loop().time() + 10.0
        while len(captured) < 2 and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.1)

        assert len(captured) == 2, (
            f"expected started + failed on {subject_filter!r} within 10s; got "
            f"{len(captured)}: subjects={[m.subject for m in captured]!r}"
        )

        events_by_type: dict[str, Any] = {}
        for msg in captured:
            decoded = json.loads(msg.data)
            events_by_type[decoded["event_type"]] = (msg, decoded)
        assert set(events_by_type.keys()) == {"started", "failed"}, (
            f"expected event types started+failed, got {set(events_by_type.keys())!r}"
        )

        # The failed event must carry the right stage + error_class.
        failed_msg, failed_payload = events_by_type["failed"]
        assert failed_msg.subject == f"events.tenant.{tenant_id}.investigation.failed"
        assert failed_payload["event_type"] == "failed"
        assert failed_payload["tenant_id"] == tenant_id
        assert failed_payload["stage"] == "spawn"
        assert failed_payload["error_class"] == "RuntimeError"
        # Header round-trip on the failed event too.
        assert failed_msg.headers is not None
        assert failed_msg.headers.get(CORRELATION_ID_HEADER) == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"

        # The started event preceded the failure (same investigation_id
        # ties them together).
        started_id = events_by_type["started"][1]["investigation_id"]
        failed_id = failed_payload["investigation_id"]
        assert started_id == failed_id

        # D.7's existing failure semantics preserved: NO filesystem
        # artifacts are written when Stage-2 fails before Stage-6 (the
        # workspace exists but the 4 contract artifacts don't).
        ws = Path(contract.workspace)
        assert not (ws / "incident_report.json").is_file()
    finally:
        with contextlib.suppress(Exception):
            await sub.unsubscribe()
        await engine.dispose()
