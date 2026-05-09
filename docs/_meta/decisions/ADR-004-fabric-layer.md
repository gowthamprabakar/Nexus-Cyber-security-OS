# ADR-004 — Fabric layer: NATS JetStream with five named buses and OCSF on the wire

- **Status:** accepted
- **Date:** 2026-05-09
- **Authors:** Architect, Platform Eng, AI/Agent Eng
- **Stakeholders:** all engineers; SRE / platform; security & compliance

## Context

The platform architecture document defines two planes (control + edge), 18 agents, ~8 OSS scanners, multiple memory engines, ChatOps approvals, audit trails, and self-evolution feedback loops — but **specifies no integration substrate** between them. The total fabric mention across the architecture document set is two lines:

- [`build-roadmap.md:11`](../../superpowers/plans/2026-05-08-build-roadmap.md#L11) tech stack: _"NATS / Redis Streams"_ (one bullet).
- [`agent_specification_with_harness.md:55`](../../agents/agent_specification_with_harness.md#L55): _"Message queue for delegation (NATS or Redis Streams)"_ — only for Supervisor delegation.

The platform-architecture diagrams show isolated components linked by unnamed arrows. Edge ↔ control plane is described as _"outbound mTLS HTTPS, gRPC stream"_ — a transport, not a fabric.

Five concrete consequences of this gap, observable today:

1. Each new scanner forces ad-hoc point integration with each consuming agent.
2. Findings have no canonical schema. [`packages/agents/cloud-posture/src/cloud_posture/schemas.py`](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py) is per-agent; by agent #5 we'll have re-invented OCSF five times.
3. Async ChatOps approval flows + cross-plane audit replication have no defined transport.
4. Self-evolution / Meta-Harness has no clean way to subscribe to reasoning traces — it has to reach into other services.
5. Air-gap mode would require a parallel transport stack instead of being a deployment-topology variation of the same fabric.

## Decision

Adopt **NATS JetStream as the platform fabric** in both planes. Define **five named buses** with explicit subject conventions, schemas, retention, and ACLs. Adopt **OCSF v1.3 as the canonical finding wire format** on `findings.>`.

### The five buses

| Subject root  | Direction / scope                    | Retention            | Ordering             | Purpose                                                                                     |
| ------------- | ------------------------------------ | -------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `events.>`    | Within-plane pub/sub                 | 7 days               | per-subject          | Agent ↔ service general events; tenant-scoped subjects (`events.tenant.<id>.<type>`)        |
| `findings.>`  | Within-plane + replicated to control | 90 days hot, S3 cold | per-tenant per-asset | Normalized findings (OCSF v1.3 envelope). Every scanner adapter and every agent emits here. |
| `commands.>`  | Control plane → edge plane           | 30 days              | per-edge             | Signed rule packs, NLAH updates, fleet commands, kill-switch. ACK-required.                 |
| `approvals.>` | Cross-plane, async                   | 365 days             | strict per-finding   | Tier-2 ChatOps approval loop. Outlives reconnects.                                          |
| `audit.>`     | Append-only, mirrored upstream       | 7 years              | strict per-tenant    | Hash-chained signed audit log. KMS-signed messages. Read-only consumers.                    |

### Topology

```
CONTROL PLANE (Nexus AWS)            EDGE PLANE (per customer)
┌──────────────────────────┐         ┌──────────────────────────┐
│ NATS JetStream Cluster   │◄────────│ NATS JetStream (single)  │
│ - hub for all tenants    │  leaf   │ - persistent, local       │
│ - replicated to S3       │  node   │ - leaf node to control   │
│ - KMS-signing for audit  │  mTLS   │ - mirrors audit upstream │
└──────────────────────────┘ outbnd  └──────────────────────────┘
                              only
```

- **Outbound-only mTLS** from edge: NATS leaf-node connection over TLS to control. No inbound to edge. Same security stance as today's hand-rolled gRPC, but with replay, durability, and a real consumer model.
- **Air-gap = leaf-node disconnected.** Same code path; the edge JetStream operates standalone, audit & findings buffer locally, replay on reconnect (or signed-bundle export for cross-domain transfer). Air-gap is no longer a separate codebase.

### Wire format

- All `findings.>` messages: **OCSF v1.3 base event** + a small `nexus_envelope` extension carrying `correlation_id`, `tenant_id`, `agent_id`, `nlah_version`, `model_pin`, `charter_invocation_id`. OCSF is what Prowler already emits, what AWS Security Lake consumes, what the broader industry is converging on.
- All other buses: protobuf schemas in `packages/shared/proto/`, versioned by file. Breaking changes are new files; compatibility is enforced at CI.

### Mandatory cross-cutting

- **`correlation_id`** on every message. One ID flows from scanner result → finding → agent reasoning trace → remediation → audit. Implementation lives in `packages/charter/src/charter/correlation.py` (to be added).
- **Per-tenant subject scoping.** ACLs enforce that consumers see only their tenant's subjects. Cross-tenant fanout is explicit (control-plane services with audited cross-tenant SCPs).

### What changes immediately

- `packages/agents/cloud-posture/src/cloud_posture/schemas.py` (the per-agent Finding model) becomes a thin Python typing layer over OCSF, _not_ a parallel schema. Refactored as part of the next session before F.3 Task 7.
- A new package `packages/shared/src/shared/fabric/` provides the JetStream client, subject builders, and OCSF envelope helpers. F.3 Task 7 (Findings → Markdown) consumes it.
- Edge transport (E.1 / E.2) is re-scoped: instead of "Go binary with a hand-rolled gRPC stream," it's "Go binary with NATS leaf-node + JetStream consumers." Net less code.

## Consequences

### Positive

- New agent or new scanner = new subscriber, no other code touched.
- OCSF on the wire deletes the per-agent re-normalization tax and aligns us with AWS Security Lake / OCSF-emitting partners.
- Self-evolution is a normal subscriber on `audit.>` instead of a special pipeline.
- Air-gap = topology config, not a parallel build.
- One `correlation_id` makes the audit chain reconstructible end-to-end. Today the chain is per-charter-invocation; this extends it across the platform.
- Backpressure, retry, dedup get one implementation each instead of N.

### Negative

- NATS JetStream is one more piece of operational surface area (clustering, monitoring, ACL admin). Mitigation: single binary, Go-native, simple ops profile relative to Kafka.
- OCSF schema evolves quickly; we must pin the version (v1.3 today) and own the upgrade path.
- Engineers must learn subject naming conventions and schema discipline. We will document this in `packages/shared/proto/README.md` and gate via CI lint.

### Neutral / unknown

- Exact JetStream cluster sizing for Phase 1a (5–10 customers) — pending sizing doc. Likely: 3-node R6i.large in control plane, single-node per edge.
- Whether to keep ClickHouse `findings.>` consumer as a separate service or co-locate. Decided when the first non-Cloud-Posture findings consumer ships.

## Alternatives considered

### Alt 1: Kafka

- Why rejected: heavier ops, JVM, more nodes for same throughput. JetStream's leaf-node feature is a near-perfect fit for outbound-only edge↔control without any custom protocol. Kafka MirrorMaker is the analogue but adds a separate process to operate.

### Alt 2: Redis Streams

- Why rejected: less durable, less feature-complete (no native leaf-node, no native protobuf schema registry, less robust replay). Acceptable for the original "supervisor delegation queue" use case but inadequate for findings + audit + cross-plane.

### Alt 3: Hand-rolled gRPC streams (status quo)

- Why rejected: re-implements the fabric for each producer/consumer pair. No replay. No durable consumer groups. Audit replication becomes a second project. The two existing lines of architecture text are not a fabric.

### Alt 4: Cloud-vendor pub/sub (SNS+SQS, EventBridge, Pub/Sub)

- Why rejected: ties the platform to one cloud, breaks edge-plane portability across customer cloud choices, breaks air-gap entirely.

### Alt 5: Custom in-process EventBus (no broker)

- Why rejected: only solves intra-process. Cross-plane and durable-replay needs are unmet.

## References

- ADR depends on: [ADR-001 monorepo-bootstrap](ADR-001-monorepo-bootstrap.md) — `packages/shared/` is the home for fabric client + protobufs.
- ADR depended on by: [ADR-005 async tool wrapper convention](ADR-005-async-tool-wrapper-convention.md) — fabric clients are async.
- New plan to add: **P0.10 — Scanner Adapter Framework + OCSF envelope**. Owned by Detection Eng + Platform Eng. Must land before F.3 Task 7.
- Plan changes: F.3 Task 7 (Findings → Markdown summarizer) and Task 10 (agent driver) re-baseline against OCSF + fabric. Refactor of [`schemas.py`](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py) tracked as part of those tasks.
- Edge plane plans E.1 / E.2 re-scoped against this ADR.
- OCSF reference: <https://schema.ocsf.io/1.3.0/>
