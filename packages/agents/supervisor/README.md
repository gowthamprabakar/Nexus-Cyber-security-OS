# Nexus Supervisor Agent (#0)

**Status:** v0.1 — 15/16 tasks merged; final closure (verification record) is Task 16.

> **v0.2 — operator Cycle 12 (`__version__` 0.1.0 → 0.2.0, 2026-06-12).** The platform-orchestration cycle; closing supervisor v0.2 brings the fleet to **12 of 17 agents at v0.2 (~71%)**. Supervisor is the **dispatcher class** — keeping its **by-design deviation** (ADR-007): **no Charter wrap, no ToolRegistry, no OCSF emission** (it emits F.6 audit vocabulary + `supervisor_report.md` + escalation files) — PRESERVED throughout (WI-O11). This cycle adds, all additively: **live multi-agent dispatch** (`routing/` — a `live_registry` of the 11 closed-cycle v0.2 agents (full) + remaining built agents (basic, Q1), `live_dispatch` plan/execute via the injectable invoker, `orchestration` with dependency-ordered waves — compliance after the posture agents); **per-agent concurrency** (`concurrency/` — default cap 4, operator overrides, timeout backpressure, Q2); **failure classification + bounded retry** (`failure/` — transient/permanent/timeout; transient retries at most once, H4, Q3); an **additive F.6 audit vocabulary** (`audit_emit.py` — 4 → 8 entries; the existing 4 byte-identical, WI-O5/Q4); a **SQLite/WAL scheduled queue** (`queue/` — durable store + transactional drainer with crash recovery, Q5); and **event-driven + heartbeat coexistence** (`triggers/` — both modes, routing independent of trigger source, Q6). Two new **code-level invariants**: `hierarchy.assert_no_peer_to_peer` (WI-O8/H2 — only Agent #0 dispatches) + `contract_signing.assert_signed_contract` (WI-O9 — every delegation HMAC-signed + tamper-evident). The `_FORBIDDEN_SUBSCRIPTIONS` fence (never subscribe to `claims.>`, WI-O10) is preserved at the new event-listener layer too. Setup: [`runbooks/`](runbooks/); per-agent coverage (no aggregate, WI-O1) + the closure record under `docs/_meta/supervisor-v0-2-*`.
>
> **Honest scope (WI-O3 / Path 1):** continuous orchestration is **INFRASTRUCTURE** at v0.2; wiring the live dispatch loop (event-driven preemption of heartbeat, real production triggers) into `agent.run()` is the **Phase C consolidated retrofit** (after all 17 v0.2 cycles), NOT a v0.3 carry-forward. Per-tenant concurrency (Q2), the full circuit-breaker (Q3), F.6 chain read-integration (Q4), and a Postgres-backed queue via F.5 (Q5) are v0.3+.

**The platform orchestrator** — the seventh and FINAL unbuilt agent under the [Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md). Closes the breadth-first push at **17/17 agents at v0.1** once Task 16 lands.

Routes incoming work to the right specialist, fans out pre-declared independent tasks in parallel, emits to F.6 audit chain, escalates on timeout. **Ruthlessly read-only against speculation in v0.1** — structurally fenced from `claims.>` via the substrate ACL added in Task 8 (the only SAFETY-CRITICAL PR in v0.1).

## v0.1 surface (5 capabilities)

1. **Declarative routing** via `routing/agents.md` — no LLM in the routing path.
2. **Parallel dispatch** of pre-declared independent tasks (`asyncio.Semaphore(MAX_PARALLEL_DISPATCH=5)`); NOT multi-agent planning.
3. **Time-boxing** per F.1 charter budgets; one attempt per delegation, no auto-retry.
4. **F.6 audit chain** emit — 4 additive audit-action vocabulary entries.
5. **60-second heartbeat loop**, single-threaded per customer via `fcntl.flock`.

## Architecture (5-stage pipeline + outer heartbeat loop)

```
                        ┌──────────────────────────────────────┐
                        │ Heartbeat loop (every 60s; injectable)│
                        │ Single-threaded per customer via      │
                        │ fcntl.flock on customer_id.lock       │
                        └─────────┬─────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ Supervisor 5-stage pipeline (agent.run, per tick)                │
│                                                                  │
│  1. INGEST     — events.> bus / scheduled queue / CLI            │
│                  (metadata-only; WI-4 — no OCSF payload)         │
│  2. ROUTE      — pure-function rule engine; precedence:          │
│                  target_agent_declared > task_type > delta_type  │
│                  -> RoutingDecision[]                            │
│  3. DISPATCH   — Semaphore(5) parallel; F.1 budget-enforced;     │
│                  one attempt each                                │
│  4. AUDIT      — 4 additive F.6 audit-action entries             │
│                  (heartbeat.started / .dispatched / .completed   │
│                   / .escalation.raised)                          │
│  5. HANDOFF    — supervisor_report.md + per-escalation           │
│                  notification markdowns                          │
└──────────────────────────────────────────────────────────────────┘
```

Read-only against speculation (Q-ARCH-1): no `claims.>` subscription anywhere. The substrate ACL in `packages/shared/src/shared/fabric/client.py` keyed by `agent_id="supervisor"` raises `ForbiddenSubscriptionError` if any code path attempts it.

## Smoke runbook (3 steps)

These are the three commands a maintainer runs to verify a clean local check-out. Each step is independent + idempotent. Run them from the repository root.

### 1. Unit tests + gates

```sh
uv run pytest packages/agents/supervisor/tests/ -q
uv run ruff check packages/agents/supervisor/
uv run ruff format --check packages/agents/supervisor/
uv run mypy --strict packages/agents/supervisor/src
```

Expected: **226 passed**; ruff clean; mypy --strict 0 errors across 14 source files. Counts grow over time — the load-bearing assertion is "no failures."

### 2. Eval suite (15 routing-test cases)

```sh
uv run supervisor eval
```

Expected: `15/15 passed`. Each case exercises a distinct routing behavior (10 happy-path-per-specialist + 5 edge-cases: no-target-agent / ambiguous / forbidden / over-capacity / escalation-on-budget). All 15 also pass the WI-3 byte-equal-across-reruns probe in `tests/test_stub_harness.py`.

### 3. Live heartbeat against scheduled-queue

```sh
# Enqueue a task.
uv run supervisor schedule \
  --customer-id smoke \
  --task-id smoke-$(date +%s) \
  --target-agent cloud_posture

# Drain it with a single tick.
uv run supervisor heartbeat-once --customer-id smoke
```

Expected: a one-line digest like `tick=<ulid> triggers=1 delegations=1 (1 successful) escalations=0` plus a `supervisor_report.md` + `audit.jsonl` in the current directory. Subsequent ticks against the same customer cleanly drain whatever the operator queues.

## CLI

Four subcommands; full surface documented in [docs/superpowers/plans/2026-05-21-supervisor-v0-1.md](../../../docs/superpowers/plans/2026-05-21-supervisor-v0-1.md):

```sh
supervisor eval [CASES_DIR]                           # default: bundled eval/cases (15/15)
supervisor heartbeat-once --customer-id ID            # one-shot tick; drains queue + optionally
    [--task-id ID --target-agent AGENT]               # injects one operator-CLI task
supervisor schedule --customer-id ID --task-id ID     # enqueue to file-backed JSON queue
    [--target-agent AGENT | --task-type TYPE | --delta-type TYPE]
supervisor run --customer-id ID                       # start the 60s heartbeat loop
    [--tick-interval-seconds 60 --max-ticks N]
```

## Q-ARCH deferrals (v0.2+ surface — explicitly NOT in v0.1)

These four architectural deferrals are load-bearing. The v0.2 plan author MUST review them before re-introducing the corresponding surface.

### Q-ARCH-1: `claims.>` subscription + forbidden-subscriptions registry

**v0.1: Supervisor added to `_FORBIDDEN_SUBSCRIPTIONS`.** Task 8 was the SAFETY-CRITICAL substrate touch. Supervisor is an auto-acting agent that routes work into A.1 Remediation; reading speculation from `claims.>` would launder hypotheses into action — exactly the failure mode [ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md) was designed to prevent.

**WI-5 forward-carry (load-bearing).** When A.4 v0.2 introduces NLAH auto-deploy, the A.4 v0.2 plan author MUST add `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})` before any auto-acting code lands. **Three forbidden subscribers eventually**: A.1, Supervisor (this v0.1), A.4 v0.2+.

### Q-ARCH-2: A.4 introspection coupling for routing — NOT in v0.1

Supervisor routes via declarative rules in `agents.md`, not via A.4's `parse_nlah_dir` output. Cross-agent introspection coupling is premature for v0.1 — A.4's introspection is for batch eval + A/B comparison, which is a different use case. Deferred to **Supervisor v0.2** _if_ LLM-assisted routing ever needs persona context.

### Q-ARCH-3: `customer_context.md` write capability — NOT in v0.1

Read-only in v0.1 (used for routing context: authorization profile / change windows / compliance focus). Writes deferred to **Supervisor v0.2** with explicit operator approval gate — the deepest-review surface in the v0.2 conversation.

### Q-ARCH-4: routing-engine substrate hoist — NOT in v0.1

`routing/router.py` lives under `packages/agents/supervisor/src/supervisor/routing/`, NOT under `packages/shared/` or `packages/charter/`. Per ADR-007's 3rd-consumer hoist rule. If a future agent ever needs declarative routing primitives, hoist with a one-paragraph rationale in the hoist PR.

## Watch-items (carried to verification record)

- **WI-1: Substrate sealed except Task 8.** `git diff --stat packages/charter/ packages/shared/` empty across Tasks 1-7 + 9-16. The Task 8 substrate diff is bounded to `_FORBIDDEN_SUBSCRIPTIONS["supervisor"]` + ADR-012 doc amend.
- **WI-2: Single-tenant default.** `semantic_store=None` throughout; no cross-tenant reads. Heartbeat per-customer-locked via `fcntl.flock`.
- **WI-3: Stub-LLM determinism.** Per-case `responses.json` (15 files; all empty arrays since routing is rule-based). Byte-equal across reruns probe per case.
- **WI-4: No NLAH writes + no OCSF payload reads.** Router only inspects four envelope keys on `IncomingTask`; never opens OCSF payload bodies. Smoke source-grep guards catch any regression.
- **WI-5: Forward-carry — three forbidden subscribers.** Verification record names A.1 + Supervisor (this v0.1) + A.4 v0.2+ verbatim.
- **WI-6: No LLM + no A.4-introspection coupling in routing path.** Smoke test asserts `charter.llm_adapter` is not imported anywhere under `routing/` or `dispatch.py`, AND `meta_harness.tools.nlah_parser` is not imported anywhere in supervisor source.

## Out of scope (v0.1) — explicit version-named deferrals (8 items)

1. **NO LLM-driven routing.** Deferred to **Supervisor v0.2**.
2. **NO multi-agent planning.** Deferred to **Supervisor v0.3+**.
3. **NO `customer_context.md` writes.** Deferred to **Supervisor v0.2** with operator approval gate.
4. **NO auto-retry on delegation failure.** Deferred to **Supervisor v0.2**.
5. **NO cron scheduler.** File-backed queue only. Cron deferred to **Supervisor v0.2**.
6. **NO F.5 SemanticStore reads.** Deferred to **Supervisor v0.2+**.
7. **NO subprocess specialist isolation.** In-process only. Deferred to **Supervisor v0.2+**.
8. **NO multi-tenant production.** Blocks on future `SET LOCAL $1` tenant-RLS substrate-fix.

## Conformance pointers

- [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md) — monorepo
- [ADR-005](../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md) — async tool wrappers
- [ADR-006](../../../docs/_meta/decisions/ADR-006-llm-adapter.md) — LLM adapter (Supervisor doesn't consume an LLM in v0.1)
- [ADR-007 v1.1 + v1.2](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — reference NLAH agent (Supervisor is the 13th agent against v1.2)
- [ADR-008](../../../docs/_meta/decisions/ADR-008-eval-framework.md) — eval framework (17th nexus_eval_runners entry; A.4 batch-eval picks up automatically at close)
- [ADR-010](../../../docs/_meta/decisions/ADR-010-within-agent-version-extension.md) — additive audit-action vocabulary (4 new entries)
- [ADR-011](../../../docs/_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) — one-PR-per-task; Task 8 was the only SAFETY-CRITICAL PR in v0.1
- [ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md) — `claims.>` subject namespace + subscriber-ACL (Supervisor v0.1 extends the registry to its `agent_id`)

## Platform support

Linux + macOS. Windows support deferred to v0.2+ pending an `fcntl.flock` replacement (Windows uses `msvcrt.locking` semantics; the heartbeat lock + scheduled-queue file lock both depend on `fcntl`).

## Plan + verification

- **Plan:** [docs/superpowers/plans/2026-05-21-supervisor-v0-1.md](../../../docs/superpowers/plans/2026-05-21-supervisor-v0-1.md)
- **Verification record** (lands in Task 16): `docs/_meta/supervisor-v0-1-verification-2026-05-21.md` — closes the loop at **17/17 platform-complete-narrow-depth.**
