# F.7 fabric runtime — operator runbook

Owner: platform / fabric on-call · Audience: an operator bringing the NATS JetStream bus up in dev, staging, or production · Last reviewed: 2026-05-17.

This runbook covers the **substrate operation** of the F.7 v0.1 fabric runtime: how to bring NATS up, how to call `JetStreamClient` from agent code, what each of the 5 ADR-004 buses carries and for how long, how `correlation_id` flows from a producer to a header on the wire, and what's deferred to F.7 v0.2+.

> **Status:** v0.1 — substrate live, no agent migrated yet. The bus is reachable and exercised by the `NEXUS_LIVE_NATS=1` integration lane; **no production agent is publishing or subscribing on it.** D.7 migration onto `events.>` is v0.2 (separate plan); Cloud-Posture / D.5 / D.6 finding handoffs onto `findings.>` are v0.3+ (separate plans). That separation is non-negotiable and named in the [F.7 v0.1 plan's hard scope boundary](../superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md#goal).

---

## 1. What F.7 v0.1 ships

After F.7 v0.1 closes:

- **NATS JetStream is reachable** in dev via `docker/docker-compose.dev.yml`'s `nats` service (single-node, persistent volume, healthchecked). Production cluster shape is an E.x track concern; v0.1 doesn't add cluster-aware logic.
- **5 ADR-004 streams are declared** in [`packages/shared/src/shared/fabric/streams.py`](../../packages/shared/src/shared/fabric/streams.py) as `StreamSpec` frozen dataclasses with the retention values from ADR-004's "The five buses" table.
- **An async client** lives at [`packages/shared/src/shared/fabric/client.py`](../../packages/shared/src/shared/fabric/client.py) wrapping nats-py's JetStream API: `connect()`, `ensure_streams()`, `publish()`, `publish_finding()`, `subscribe()`, `close()`, plus three typed exceptions (`FabricConnectionError`, `StreamSpecMismatchError`, `MissingCorrelationIdError`).
- **`correlation_id` is enforced at the publish boundary** — every message on the bus carries a `Nexus-Correlation-Id` header. Producers either pass the kwarg explicitly or rely on `shared.fabric.correlation.correlation_scope()`'s contextvar fallback.
- **The `NEXUS_LIVE_NATS=1` integration lane** ([`test_fabric_client_live.py`](../../packages/shared/tests/integration/test_fabric_client_live.py)) proves the substrate end-to-end: connect → ensure_streams → publish → subscribe → callback receives payload + header against a real broker. Mocked unit coverage (53 tests in [`test_fabric_client.py`](../../packages/shared/tests/test_fabric_client.py)) proves the contract per-method.

**Not in v0.1:** no agent migrated onto the bus; no KMS-signed `audit.>` messages; no tenant ACL enforcement via NATS auth tokens; no pull / ordered / queue-group consumers. Each is a named v0.x deferment in the [F.7 v0.1 plan's Defers table](../superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md#defers).

---

## 2. Starting NATS locally

### 2a. Canonical path — Docker Compose

The `nats` service in [`docker/docker-compose.dev.yml`](../../docker/docker-compose.dev.yml) is the canonical dev path:

```bash
docker compose -f docker/docker-compose.dev.yml up -d nats
```

This brings up `nats:2.10-alpine` with JetStream enabled (`-js`), the data dir bind-mounted to `./.data/nats` (so the 5 streams + any buffered messages survive `docker compose down/up`), and the monitoring port exposed on `8222`. Confirm the broker is healthy:

```bash
docker compose -f docker/docker-compose.dev.yml ps nats          # expect: healthy
curl -sf http://localhost:8222/healthz                            # expect: {"status":"ok"}
nc -zv localhost 4222                                             # expect: succeeded
```

The healthcheck wired into the compose service uses BusyBox `wget` against `:8222/healthz` (5s interval / 3s timeout / 5 retries / 5s start_period). The service reaches `healthy` within ~5-10s on a warm host.

### 2b. Alternative — standalone `nats-server` binary

If Docker isn't available (Mac without Docker Desktop, CI runner without daemon), the brew binary works equivalently:

```bash
brew install nats-server
nats-server -js \
  --store_dir /tmp/nexus-nats-jetstream \
  --port 4222 \
  --http_port 8222
```

> **Version note:** the brew-installed `nats-server` may be ahead of the `nats:2.10-alpine` image pinned in the compose file (today, brew ships `v2.14.0` vs the image's `v2.10.x`). The JetStream protocol is stable across these and the F.7 v0.1 live-lane integration tests pass on both. If you need to reproduce the exact image's version locally, use Docker; for ad-hoc development, the brew binary is sufficient. This deviation is disclosed, not silent — Task 6's verification record names it explicitly.

### 2c. Production

Single-node v0.1 deployments work as long as a JetStream-enabled NATS reachable at `nats://<host>:4222` is configured. Clustering (3-node R6i.large or similar) is a production-deployment concern owned by the E.x edge-plane / SRE track, not v0.1.

---

## 3. Using `JetStreamClient` from agent code

The client is async-only (ADR-005 convention). Minimal end-to-end shape:

```python
import asyncio
from shared.fabric import (
    EVENTS_STREAM,
    JetStreamClient,
    correlation_scope,
    new_correlation_id,
)


async def main() -> None:
    client = JetStreamClient(servers=["nats://localhost:4222"])
    try:
        await client.connect()                                   # 5s timeout (Q7)
        await client.ensure_streams()                            # idempotent (Q2)

        # Publish under an explicit correlation_id.
        await client.publish(
            EVENTS_STREAM,
            "events.tenant.acme.scan_completed",
            b'{"finding_count": 42}',
            correlation_id="01J7-cid-explicit",
        )

        # OR: open a correlation_scope and let the contextvar carry it.
        with correlation_scope(new_correlation_id()):
            await client.publish(
                EVENTS_STREAM,
                "events.tenant.acme.scan_started",
                b'{}',
            )                                                    # no kwarg needed

        # Subscribe with a durable push consumer.
        async def on_event(msg) -> None:
            cid = msg.headers.get("Nexus-Correlation-Id")
            print(f"received correlation_id={cid!r} data={msg.data!r}")
            await msg.ack()

        await client.subscribe(
            EVENTS_STREAM,
            "events.tenant.acme.>",
            on_event,
            durable_name="acme-events-consumer",
        )

        await asyncio.sleep(60)                                  # let the consumer run
    finally:
        await client.close()


asyncio.run(main())
```

A few notes on the surface:

- `connect()` raises `FabricConnectionError` after a 5-second timeout. The client does **not** silently fall back to filesystem / in-process delivery — connect failure is the operator's signal that the bus isn't reachable, not a behaviour the client compensates for.
- `ensure_streams()` is idempotent on connect. Missing streams are created with the declared `StreamConfig`. Existing streams whose config drifts from the spec (subjects / max_age / discard policy) raise `StreamSpecMismatchError`; the client never overwrites. Operators reconcile manually — see §4.
- `publish()` rejects subjects that don't lie under the target stream's namespace (e.g., `events.foo` against `FINDINGS_STREAM` raises `ValueError` at the publish boundary, not silently routes to the wrong stream).
- `publish_finding(subject, ocsf_event, envelope)` is the OCSF-wire-format helper for `findings.>`. It wraps the OCSF event with the `NexusEnvelope`, JSON-encodes deterministically (`sort_keys=True` + `separators=(",",":")`) so two equivalent dicts produce identical bytes, and forwards the envelope's `correlation_id` to `publish()`'s precondition.
- `subscribe()` requires a `durable_name` (positional ephemeral consumers aren't supported in v0.1).

---

## 4. The 5 streams + retention (copied from ADR-004)

| Subject root  | Direction / scope                    | Retention            | Ordering             | Purpose                                                                                     |
| ------------- | ------------------------------------ | -------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `events.>`    | Within-plane pub/sub                 | 7 days               | per-subject          | Agent ↔ service general events; tenant-scoped subjects (`events.tenant.<id>.<type>`).       |
| `findings.>`  | Within-plane + replicated to control | 90 days hot, S3 cold | per-tenant per-asset | Normalised findings (OCSF v1.3 envelope). Every scanner adapter and every agent emits here. |
| `commands.>`  | Control plane → edge plane           | 30 days              | per-edge             | Signed rule packs, NLAH updates, fleet commands, kill-switch. ACK-required.                 |
| `approvals.>` | Cross-plane, async                   | 365 days             | strict per-finding   | Tier-2 ChatOps approval loop. Outlives reconnects.                                          |
| `audit.>`     | Append-only, mirrored upstream       | 7 years              | strict per-tenant    | Hash-chained signed audit log. KMS-signed messages. Read-only consumers.                    |

A few notes for operators:

- **Ordering granularity comes from subject design, not stream config.** JetStream provides per-subject FIFO unconditionally; the named granularity in the table above (per-tenant per-asset, per-edge, etc.) is realized by the subject builders in [`shared.fabric.subjects`](../../packages/shared/src/shared/fabric/subjects.py) (e.g., `findings.tenant.<tid>.asset.<sha256[:16]>` realizes per-tenant per-asset FIFO).
- **`StreamSpecMismatchError` recovery.** If `ensure_streams()` raises this on connect, the broker has an existing stream whose `subjects` / `max_age` / `discard` differs from the declared `StreamSpec`. The client does not overwrite. Two safe paths:
  1. **Delete and re-create** if the broker's stream has no messages you need to preserve:
     ```bash
     nats stream rm <stream-name>
     # then re-run the agent so ensure_streams() recreates it
     ```
  2. **Update the declaration** in `shared/fabric/streams.py` if the broker's shape is the one you want to keep, and ship the change as an F.7 v0.x extension under ADR-010.
- **`audit.>` discard policy.** v0.1 uses `discard="old"` (drop oldest at retention boundary). Hardening to `discard="new"` (refuse new publishes; backpressure producers) is a v0.x deferment — relevant if audit-message loss is unacceptable in a specific deployment.

---

## 5. `correlation_id` as a bus property

Every message on every stream is required to carry a `Nexus-Correlation-Id` NATS header. `JetStreamClient.publish()` enforces this at the publish boundary so producers can't bypass the contract.

### 5a. Resolution order

`publish()` resolves the correlation_id in this order:

1. **Explicit `correlation_id=` kwarg** if non-None. Always wins. Use this when minting a new root id for an audit-chain anchor message.
2. **`shared.fabric.correlation.current_correlation_id()`** if the caller is inside a `correlation_scope`. The "ambient id" path.
3. **Both absent → raise `MissingCorrelationIdError`** before the network call. The message never reaches the broker.

### 5b. Setting the contextvar from agent code

The contextvar pattern is the recommended path for agents that already have a correlation_id flowing through their call graph. Wrap the publish boundary in `correlation_scope`:

```python
from shared.fabric import correlation_scope, new_correlation_id

# At the top of an agent invocation:
with correlation_scope(new_correlation_id()):
    await scan_aws_account(...)          # any nested publish() calls
                                          # automatically carry this id
```

The contextvar is asyncio-task-isolated (per `shared.fabric.correlation`'s implementation), so two concurrent task-spawned operations carry independent ids without interference.

### 5c. Reading the header on the consume side

Consumers read `msg.headers["Nexus-Correlation-Id"]` directly — no per-stream payload unwrap needed. Example callback:

```python
async def on_message(msg) -> None:
    cid = msg.headers.get("Nexus-Correlation-Id")
    if cid is None:
        # Defensive: should never happen because publish() refuses without
        # one, but a future v0.x bridge from a non-Nexus producer might
        # not enforce it. Log and ack to avoid redelivery loops.
        logger.warning("message on %s without correlation_id", msg.subject)
    # ... process under cid ...
    await msg.ack()
```

For `findings.>`, the correlation_id is **also** carried inside the OCSF envelope (the `nexus_envelope.correlation_id` field). The header is the canonical wire-level read; the envelope field is for consumers that want the full envelope shape for cross-correlation with other envelope fields (`tenant_id`, `agent_id`, `nlah_version`, etc.).

---

## 6. What's deferred

The F.7 v0.1 plan's [Defers table](../superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md#defers) names eight items explicitly so future plans inherit them. Operator-relevant summary:

| Deferred to                  | Item                                                           | When it matters to operators                                                                                        |
| ---------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| F.7 v0.2                     | D.7 Investigation migration onto `events.>`                    | First consumer migration. Operators running D.7 will see it consuming the bus instead of filesystem snapshots.      |
| F.7 v0.3+                    | Cloud-Posture / D.5 / D.6 finding handoffs onto `findings.>`   | Each detect agent's migration is its own within-agent version extension under ADR-010.                              |
| F.7 v0.x                     | KMS-signed `audit.>` messages                                  | Hardening; relevant if your deployment requires non-repudiation of audit messages at the wire level.                |
| F.7 v0.x                     | Tenant ACL enforcement via NATS auth tokens                    | Today, subject-scoping is at builder level. Broker-level ACL enforcement is hardening for multi-tenant deployments. |
| F.7 v0.x                     | Protobuf schemas for `events.>` / `commands.>` / `approvals.>` | Wire-format discipline. Lands when each stream's first consumer defines what messages it expects.                   |
| F.7 v0.x                     | Replay / dedup / backpressure beyond NATS defaults             | Production tuning. Defaults are adequate for v0.1 substrate validation.                                             |
| E.1 + E.2 (edge plane track) | Leaf-node outbound mTLS edge ↔ control                         | Edge track owns this; v0.1 is single-plane substrate.                                                               |
| E.1 + E.2 (edge plane track) | Air-gap leaf-disconnected operation                            | Same.                                                                                                               |

---

## 7. Live-lane test invocation (for operators reproducing the substrate proof)

To re-prove the substrate on a fresh environment:

```bash
# 1. Bring NATS up (per §2a or §2b).
docker compose -f docker/docker-compose.dev.yml up -d nats

# 2. Run the gated lane.
NEXUS_LIVE_NATS=1 uv run pytest \
    packages/shared/tests/integration/test_fabric_client_live.py -v
```

Expected: 4 passed (connect+ensure_streams; publish→subscribe round-trip with header; contextvar fallback on the wire; publish_finding round-trip).

Without `NEXUS_LIVE_NATS=1`, the lane SKIPs with a reason naming the env var + the compose command. The mocked lane in `test_fabric_client.py` (53 tests) runs unconditionally — the live lane is for empirical proof against a real broker; the mocked lane is the CI gate.
