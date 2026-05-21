# ADR-012 — Fabric `claims.>` subject namespace (6th bus)

- **Status:** accepted
- **Date:** 2026-05-21
- **Authors:** Platform Eng, AI/Agent Eng
- **Stakeholders:** D.12 Curiosity, A.4 Meta-Harness, Supervisor #0, all D-track agents that consume probe directives

## Context

[ADR-004](ADR-004-fabric-layer.md) defines **five named NATS JetStream buses** (`events.>`, `findings.>`, `commands.>`, `approvals.>`, `audit.>`) with explicit subject conventions, retention, and ACLs. The five buses are observed/operational — they carry telemetry, normalized findings, commands, approvals, and audit. They do **not** carry _speculative_ state — agent-proposed hypotheses, probe directives, or "scan-suggestions-yet-to-be-confirmed."

D.12 Curiosity (next agent in the [Path-B-breadth-first sequence](../../superpowers/sketches/2026-05-20-agent-version-roadmaps.md)) is the first agent that emits speculative state: it reasons over the existing `SemanticStore` + `findings.>` corpus and proposes _hypotheses_ ("the IAM posture has not been scanned in `eu-west-3` in 30 days; recommend a re-scan") and _probe directives_ ("run D.7 Investigation against finding `CSPM-...`"). These claims are conceptually distinct from findings:

- **Findings** describe observed state. Issued by scanners + posture agents. Retention 90d hot. ACLed per tenant + asset.
- **Claims** describe _proposed_ state. Issued by Curiosity (and, in time, A.4 Meta-Harness scoring proposals + Supervisor #0 routing recommendations). Retention shorter (claims that don't materialize into action expire). Different consumer set (probe-consuming agents subscribe; analytics/audit consumers don't necessarily).

The sketch flagged this as a real substrate decision:

> [§1 of the remaining-agents sketch](../../superpowers/sketches/2026-05-20-remaining-agents-sketch.md): _"A potentially new F.7 fabric subject (`claims.>` or similar) per ADR-004 — if Curiosity-hypotheses need their own bus separate from `findings.>`. This is a real substrate decision that the full plan must call out explicitly; could go either way."_

D.12 v0.1 is **blocked on this decision** per the [Path-B operating rule's substrate-exception clause](../../../packages/agents/synthesis/README.md#scope-v01) — substrate plans that unblock an unbuilt v0.1 are the only mid-sequence exception. This ADR is that substrate plan.

Three candidate resolutions were weighed:

| Approach                                           | Substrate cost                                          | Semantic clarity                                                                | Operational flexibility                                                           |
| -------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **A. New `claims.>` subject namespace** (this ADR) | small (subject builder + StreamSpec + JetStream config) | clean: observed ≠ speculative                                                   | per-bus retention + ACL + ordering                                                |
| B. Reuse `findings.>` with class_uid discriminator | zero                                                    | mixed: observed + speculative on same wire; OCSF has no native hypothesis class | inherits findings.> retention/ACL — claims forced to 90d hot + per-asset ordering |
| C. Reuse `events.>` with typed event_type          | zero                                                    | weak: events.> is the catch-all bus; not OCSF-enveloped; not per-asset ordered  | inherits events.> 7d retention — possibly correct but accidental                  |

A's substrate cost is bounded (this PR ships it). B and C punt the substrate decision but lock the semantic + operational decisions to whichever bus is reused; both are reversible only by a future migration, which is more expensive than building the right bus now.

## Decision

Amend [ADR-004](ADR-004-fabric-layer.md) to add **`claims.>` as a sixth named bus**.

### The six buses (updated)

| Subject root   | Direction / scope                    | Retention            | Ordering                 | Purpose                                                                                                                                               |
| -------------- | ------------------------------------ | -------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `events.>`     | Within-plane pub/sub                 | 7 days               | per-subject              | Agent ↔ service general events; tenant-scoped subjects (`events.tenant.<id>.<type>`)                                                                  |
| `findings.>`   | Within-plane + replicated to control | 90 days hot, S3 cold | per-tenant per-asset     | Normalized findings (OCSF v1.3 envelope). Every scanner adapter and every agent emits here.                                                           |
| `commands.>`   | Control plane → edge plane           | 30 days              | per-edge                 | Signed rule packs, NLAH updates, fleet commands, kill-switch. ACK-required.                                                                           |
| `approvals.>`  | Cross-plane, async                   | 365 days             | strict per-finding       | Tier-2 ChatOps approval loop. Outlives reconnects.                                                                                                    |
| `audit.>`      | Append-only, mirrored upstream       | 7 years              | strict per-tenant        | Hash-chained signed audit log. KMS-signed messages. Read-only consumers.                                                                              |
| **`claims.>`** | Within-plane pub/sub                 | **30 days**          | **per-tenant per-agent** | **Agent-proposed hypotheses + probe directives. Speculative state.** Emitted by D.12 Curiosity (v0.1) and, in time, A.4 Meta-Harness + Supervisor #0. |

### Subject layout

Per-agent scoping (mirrors `events.>`'s `events.tenant.<tid>.<event_type>` shape but threads the originating agent into the subject so subscribers can filter on emitter):

```
claims.tenant.<tenant_id>.agent.<agent_id>
```

- `<tenant_id>` is validated by `shared.fabric.subjects._validate_token` (alphanumeric + `_` + `-`).
- `<agent_id>` is validated the same way. v0.1 emitter is `curiosity`; future emitters (`meta_harness`, `supervisor`) follow the same convention.

Consumers subscribe to `claims.tenant.<tid>.>` (all claim emitters for a tenant) or `claims.tenant.<tid>.agent.curiosity` (specific emitter).

### Retention + discard policy

- **Retention: 30 days.** Longer than `events.>` (7 days, ephemeral lifecycle events) and shorter than `findings.>` (90 days, observed state with audit/replay value). Claims that don't materialize into a finding or a remediation within 30 days are stale; the operator should observe the staleness signal rather than the substrate retaining indefinitely.
- **Max msgs/subject: -1** (unlimited; matches the other five buses in v0.1).
- **Discard policy: `"old"`** (drop oldest when retention triggers; matches the other five v0.1 buses).

### Wire format

**Deferred to D.12 v0.1 Q1.** The substrate side (this ADR) is wire-format-agnostic — the stream catches arbitrary bytes. D.12 v0.1's plan will resolve whether claims ride the existing OCSF v1.3 envelope (with a new class*uid in OCSF's `Discovery/Reconnaissance` category, e.g. `4xxx`) or a new lightweight `nexus_claim` envelope. Both options stay open under this ADR. F.7 v0.1's Q5 — *"OCSF envelope on `findings.>` only; the other four streams accept arbitrary bytes"\_ — applies to `claims.>` too.

### ACLs

ACLs follow the existing per-tenant scoping. Producers in tenant `T` may publish to `claims.tenant.T.agent.*`. Consumers in tenant `T` may subscribe to `claims.tenant.T.>`. Cross-tenant fanout is forbidden at the broker layer (matches ADR-004's mandatory cross-cutting).

### What changes immediately

- [`packages/shared/src/shared/fabric/subjects.py`](../../../packages/shared/src/shared/fabric/subjects.py): adds `claims_subject(tenant_id, agent_id) -> str`.
- [`packages/shared/src/shared/fabric/streams.py`](../../../packages/shared/src/shared/fabric/streams.py): adds `CLAIMS_STREAM: StreamSpec`; extends `ALL_STREAMS` from 5 to 6 entries.
- F.7 v0.1's `JetStreamClient.ensure_streams()` is unchanged at the call-site — it iterates `ALL_STREAMS`, so the 6th stream is picked up automatically by every deployment.
- Tests in [`packages/shared/tests/fabric/`](../../../packages/shared/tests/fabric/) extended with subject-builder + stream-spec coverage.

### What does NOT change

- ADR-004's `findings.>` OCSF envelope contract — untouched. Claims do not flow on `findings.>`.
- The 5 existing streams' StreamSpec values — untouched.
- The `JetStreamClient` implementation — untouched (it's spec-driven).
- The audit-chain invariants — untouched (audit still owns `audit.>` exclusively).

## Consequences

### Positive

- D.12 Curiosity v0.1 is unblocked. The plan can be written and built without ambiguity about where claims flow.
- Speculative state stays separate from observed state at the substrate layer. This makes operational policies (retention, replay, replication-to-control-plane) independently tunable per concept.
- Future speculative-state agents (A.4 Meta-Harness scoring proposals, Supervisor #0 routing recommendations) have a clean home without further substrate work.
- Consumer subscription is precise: D.7 / D.5 / D.8 subscribing to `claims.>` for probe directives don't filter through unrelated `findings.>` traffic.
- ADR-004's 5-bus design was always extension-friendly (one stream-spec table, one subject-builder per bus). Adding a 6th is the well-supported extension path.

### Negative

- One more JetStream stream to operate. Mitigation: identical lifecycle to the other five — same `ensure_streams()` call, same retention model, same subject discipline. Operational delta is near-zero.
- One more subject convention engineers must internalise. Mitigation: the convention is documented inline in `subjects.py` next to the existing five, and the per-tenant per-agent scoping is the natural generalisation of `events.>`'s per-tenant per-event_type scoping.
- The wire format question (OCSF-enveloped vs custom envelope) is deferred — there's a real decision still to make. Mitigation: deferred to D.12 v0.1's Q1, which is exactly where the wire-format decision has the most context to be informed by.

### Neutral / unknown

- Exact JetStream cluster sizing impact for `claims.>` — small (claims volume is tiny relative to findings or audit), but tuning happens at production scale.
- Whether A.4 Meta-Harness + Supervisor #0 emit on `claims.>` or get their own buses — open question deferred to those agents' v0.1 plans. v0.1 D.12 is the only `claims.>` emitter.
- Whether claims should replicate to the control plane like findings do, or stay edge-local. Default in v0.1: edge-local only (no leaf-node replication). Revisit when A.4 Meta-Harness needs cross-tenant aggregation.

## Alternatives considered

### Alt 1: Reuse `findings.>` with a class_uid discriminator

- Why rejected: mixes observed and speculative state on the same wire. OCSF has no native "hypothesis" class — we'd be co-opting an existing class_uid with semantic stretch, or proposing a new one to the OCSF schema project (out of scope). Forces claims onto 90-day hot retention even when 30-day is the right operational fit. Per-asset ordering is wrong for per-agent claim streams. Reversing this later is a real migration (consumer split + re-keying).

### Alt 2: Reuse `events.>` with a typed event_type

- Why rejected: `events.>` is the catch-all within-plane bus, already crowded with lifecycle and system events. Not OCSF-enveloped — claims that consumers may want to treat similarly to findings (especially for D.7/D.5/D.8 probe-consumption) lose the envelope alignment. Not per-asset ordered, but that's a wash for claims. Net: subject-filtering becomes uglier and the operational policy (7-day retention) is accidentally correct rather than chosen.

### Alt 3: Per-agent dedicated subjects (e.g., `curiosity.>`, `meta_harness.>`)

- Why rejected: doesn't generalise — each new speculative-state agent would need a fresh subject root and a fresh stream. The shared-namespace approach (`claims.tenant.<tid>.agent.<agent_id>`) keeps the operational surface bounded at one stream while permitting per-emitter consumer filtering via subject hierarchy. Lower ceiling on cross-agent claim queries (A.4 reading all proposed claims for a tenant) under per-agent dedicated subjects.

### Alt 4: No fabric subject; persist claims to `SemanticStore` only

- Why rejected: misses the pub/sub semantics D.7/D.5/D.8 need for probe-directive consumption (they don't want to poll `SemanticStore`). Also misses the audit-replay value the fabric layer provides for "what hypothesis did Curiosity propose at time T". `SemanticStore` and `claims.>` are complementary: claims persist on the bus for consumption + replay; the `SemanticStore` carries the durable hypothesis entity for cross-reference.

## References

- ADR depends on: [ADR-004 fabric layer](ADR-004-fabric-layer.md) — this ADR amends ADR-004's "five buses" to "six buses."
- ADR depended on by: D.12 Curiosity v0.1 plan (forthcoming) — wire-format decision (OCSF vs custom envelope) is D.12 Q1.
- Related: [F.7 v0.1 verification record](../d-2-f4-verification-2026-05-11.md) and the F.7 v0.1 plan — `JetStreamClient.ensure_streams()` consumes `ALL_STREAMS` declaratively; the 6th stream is picked up without code changes there.
- Sketch context: [`docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md`](../../superpowers/sketches/2026-05-20-remaining-agents-sketch.md) §1 (D.12 substrate flag) + §8 (Path-B sequence sequencing rationale).
- Operating rule: [Path-B-breadth-first (2026-05-20)](../../superpowers/sketches/2026-05-20-agent-version-roadmaps.md) — substrate plans unblocking an unbuilt v0.1 are the only mid-sequence exception; this ADR exercises that clause.
