# Supervisor (#0) v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Supervisor Agent** (`packages/agents/supervisor/`) — the **seventh and final unbuilt agent** under the [Path-B-breadth-first operating rule](../sketches/2026-05-20-agent-version-roadmaps.md) (2026-05-20) and the **seventeenth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / D.13 / D.12 / A.4 / **Supervisor**). **The platform orchestrator** — routes incoming work to the right specialist; fans out pre-declared independent tasks in parallel; emits to F.6 audit chain; escalates on timeout. **Ruthlessly read-only against speculation in v0.1** — structurally fenced from `claims.>`.

**Scope (v0.1, locked per Path-B-breadth-first rule + the user-supplied hard guardrails).** Five allowed capabilities only:

1. **Declarative routing** — route an `ExecutionContract` to ONE specialist based on routing-table match against the incoming task's declared `target_agent` OR (when not declared) a pattern-match on task shape. **Declarative YAML/markdown rules, NOT LLM-driven.**
2. **Parallel dispatch** — fan-out to multiple specialists IN PARALLEL when the incoming task explicitly declares multiple independent sub-tasks. Capped at 5 concurrent per customer (`asyncio.Semaphore(5)`). **NOT multi-agent planning** — pre-declared independent tasks only.
3. **Time-box every delegation** per existing F.1 charter machinery. Specialist budgets are enforced; Supervisor reports the partial result if budget exceeded. **One attempt per delegation.** No auto-retry.
4. **Emit to F.6 audit chain** for every delegation (start + completion + escalation). 4 new audit-action vocabulary entries (Q6 below).
5. **Heartbeat loop every 60 seconds.** Single-threaded per customer via `fcntl.flock` distributed lock. Checks: (a) `events.>` bus subscription, (b) operator-initiated CLI invocations, (c) scheduled task queue (file-backed only — no cron).

**Nothing else in v0.1.** Eight explicit version-named deferrals are listed in §"Out of scope" below.

**Strategic role.** Supervisor is **the platform-critical-path agent**. Closing it brings the platform to **17/17 agents at v0.1** — the breadth-first push is complete. The second-pass v0.2 conversation opens at that point.

**Substrate posture.** Supervisor v0.1 makes **exactly ONE** substrate touch (Task 8): adds `_FORBIDDEN_SUBSCRIPTIONS["supervisor"] = frozenset({"claims.>"})` to `packages/shared/src/shared/fabric/client.py` + a doc-only amendment to ADR-012's "Subscriber ACL" section. This is the **SAFETY-CRITICAL** task in v0.1; every other task is LOW-RISK and agent-local.

---

## Q1 — Output shape: F.6 audit + workspace markdown only (NO bus, NO OCSF, NO NLAH writes)

**Resolution: 2 + 1 emit directions.** Mirrors A.4's read-only posture but to different destinations:

1. **F.6 audit chain** — 4 additive audit-action vocabulary entries (Q6 below). The audit chain is the canonical record of every delegation decision.
2. **`supervisor_report.md` workspace markdown** — per-tick digest covering triggers received, delegations dispatched, completion status (ok / timeout_partial / escalated), escalation summary if any.
3. **(Conditional) `escalation_<run_id>.md`** — only written when a delegation times out per F.1 budget enforcement OR a routing rule matches an "escalate-only" terminal. This is **not** a fabric publish — it's an operator notification artefact paired with the `supervisor.escalation.raised` audit entry. **Escalation = "notify human, do not attempt remediation."**

**Explicitly NOT in v0.1.** No `claims.>` publish (structurally fenced — Q-ARCH-1 below). No subject of Supervisor's own. No writes to any agent's NLAH directory (WI-4). No SemanticStore writes (Q5). No OCSF emission — Supervisor never opens an OCSF payload deeper than envelope routing-keys (WI-4 sub-clause).

## Q2 — Routing mechanism: declarative rule engine, NOT LLM-driven

**Resolution: rules in `routing/agents.md` (markdown-with-frontmatter); pure pattern-match.**

- `packages/agents/supervisor/src/supervisor/routing/agents.md` ships the routing table. Each rule entry carries `target_agent` + `match` block (declarative predicate: `target_agent_declared == "<id>"` OR `task_type == "<pattern>"` OR `delta_type == "<pattern>"`) + optional `priority` integer + `permitted_tools` list (per Q-ARCH-2 resolution — see drift item #6 in brainstorm).
- `routing/parser.py` loads the markdown into a `RoutingRule[]` pydantic structure.
- `routing/router.py` is a pure-function rule engine: takes an `IncomingTask` envelope (metadata only — never the OCSF body) + `RoutingRule[]`, returns a `RoutingDecision` (`Match(target_agent, delegation_contract)` / `NoMatch` / `Ambiguous(candidates)` / `Escalate(reason)`).
- **No LLM call anywhere in the routing path.** Smoke test asserts `charter.llm_adapter` is **not** imported by any module under `routing/` or `dispatch.py` — the LLM-anti-pattern guard.

**Supervisor v0.1 routes via DECLARATIVE rules only.** LLM-assisted routing (including any A.4 `AgentManifest` consumption for persona-aware routing) is deferred to Supervisor v0.2 (Q-ARCH-2 below).

## Q3 — Fan-out: parallel dispatch of pre-declared independent tasks (NOT planning); cap=5 per customer

**Resolution: `asyncio.gather` under `Semaphore(5)`; one delegation per declared sub-task; no decomposition.**

- `dispatch.py` exposes `dispatch_parallel(decisions: list[RoutingDecision], *, concurrency: int = 5) -> list[DelegationOutcome]`. Concurrency cap is per-customer (the heartbeat loop is single-threaded per customer via `fcntl.flock`, so the cap is naturally per-customer).
- The DIFFERENCE between "planning" and "parallel-dispatch" is enforced structurally: `dispatch_parallel` accepts a `list[RoutingDecision]` that the _caller_ (heartbeat loop) has already produced from declared sub-tasks. Supervisor never _decides_ which agents to invoke beyond what the rules + incoming task explicitly named.
- **In-process invocation** of the target specialist's `nexus_eval_runners` entry-point runner. v0.1 stays in-process to keep the failure surface narrow; subprocess isolation deferred to v0.2 once we have telemetry on what actually breaks.

## Q4 — Time-boxing + escalation: F.1 charter budget; one attempt; escalation = notify-not-retry

**Resolution: F.1 charter machinery enforces per-delegation budgets; on timeout Supervisor accepts the partial result + raises escalation; never retries.**

- Each delegation gets an `ExecutionContract` carrying budget (wall-clock / tokens / tool-calls / MB-written) per F.1 conventions. The specialist's own machinery enforces it.
- On budget exceeded: Supervisor receives a partial `DelegationOutcome(status="timeout_partial", partial_payload=..., reason=...)`. Records it in the audit chain (`supervisor.delegation.completed` with `status="timeout_partial"`) + writes an escalation markdown.
- On rule-engine `Escalate(reason)` terminal: same path — escalation markdown + audit chain entry.
- **One attempt per delegation. No auto-retry.** Re-triggering the same task is the operator's job in v0.1.

## Q5 — Tenancy + scheduled queue + state model: stateless v0.1; file-backed queue; per-customer lock

**Resolution: identical posture to every prior agent (`semantic_store=None` opt-in default), extended with a file-backed scheduled-task queue + per-customer distributed lock.**

- **`semantic_store=None` opt-in default.** Supervisor v0.1 does **not** read from F.5 SemanticStore. No customer-baseline / historical-pattern / cross-run-learning. Stateless across heartbeats.
- **F.6 audit chain is write-only.** Supervisor emits entries but does not read them for decision-making.
- **File-backed scheduled-task queue** at `<workspace_root>/.supervisor/scheduled/<customer_id>.json` (atomic-rename on dequeue, fcntl-locked appends — see drift resolution #3 below). The heartbeat loop scans this file each tick. No cron, no DB-backed queue.
- **Per-customer distributed lock** via `fcntl.flock` on `<workspace_root>/.supervisor/locks/<customer_id>.lock`. The heartbeat loop acquires + releases per tick; a concurrent Supervisor process on the same customer is forced to wait.
- **`customer_context.md` is READ-ONLY in v0.1.** Lives at `<workspace_root>/customer_context.md` (single-file shape per drift resolution #2 below). Supervisor parses YAML frontmatter for routing-relevant fields (authorization profile / change windows / compliance focus). Writes deferred to Supervisor v0.2 with explicit operator approval gate (Q-ARCH-3).

Multi-tenant production still blocks on the future `SET LOCAL $1` tenant-RLS substrate-fix plan (inherited posture).

## Q6 — Audit posture: 4 additive F.6 audit-action vocabulary entries

**Resolution: 4 new entries per [ADR-010](../../_meta/decisions/ADR-010-within-agent-version-extension.md) condition 4 (additive-only; no existing audit-action strings touched).**

- `supervisor.heartbeat.started` — every heartbeat tick start; carries `customer_id` + `tick_id` + trigger source counts (events / cli / scheduled).
- `supervisor.delegation.dispatched` — one per delegation; carries `target_agent` + `delegation_contract_id` + match rule pointer.
- `supervisor.delegation.completed` — one per delegation; carries `status` (∈ {ok, timeout_partial, error}) + `duration_sec` + budget-consumed summary.
- `supervisor.escalation.raised` — one per escalation; carries `reason` + escalation markdown path.

F.6 hash-chain semantics inherited unchanged. No substrate writes to `packages/charter/` beyond the SAFETY-CRITICAL Task-8 substrate touch in Q-ARCH-1 below.

---

## Q-ARCH acknowledgments — explicit deferrals to v0.2+ and the ONE substrate touch

### Q-ARCH-1: `claims.>` subscription + forbidden-subscriptions registry — **THE SAFETY-CRITICAL SUBSTRATE TOUCH (Task 8)**

**Supervisor v0.1 does NOT subscribe to `claims.>`** because Supervisor is an auto-acting agent that routes work into A.1 Remediation; reading speculation from `claims.>` would launder hypotheses into action — exactly the failure mode [ADR-012](../../_meta/decisions/ADR-012-claims-subject-namespace.md) was designed to prevent. Architecturally consistent with A.1: both are auto-acting; both are structurally fenced from `claims.>`.

**Task 8 (SAFETY-CRITICAL label, NO auto-merge, verified-against-HEAD discipline, manual review):**

```python
# packages/shared/src/shared/fabric/client.py
_FORBIDDEN_SUBSCRIPTIONS: dict[str, frozenset[str]] = {
    "remediation": frozenset({"claims.>"}),
    "supervisor": frozenset({"claims.>"}),   # NEW — Supervisor v0.1
}
```

Plus a doc-only amendment to **ADR-012 §"Subscriber ACL"** adding Supervisor to the forbidden-subscriber table.

**Forward-looking carry-forward to verification record (WI-5).** When A.4 v0.2 introduces NLAH auto-deploy, A.4 v0.2 plan MUST add `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})`. The full trajectory becomes **three forbidden subscribers**: A.1, Supervisor (this v0.1), A.4 v0.2+. Documented in the verification record §"Forward carries" so the A.4 v0.2 author can't miss it.

### Q-ARCH-2: A.4 introspection coupling — **NOT in v0.1**

Supervisor routes via declarative rules in `agents.md`, not via `parse_nlah_dir` output. Cross-agent introspection coupling is premature for v0.1 — A.4's introspection is for batch eval and A/B comparison, which is a different use case from routing decisions. Deferred to **Supervisor v0.2** _if_ LLM-assisted routing ever needs persona context.

Carried as **WI-6**: smoke test asserts no module under `routing/` or `dispatch.py` imports `meta_harness.tools.nlah_parser` or `charter.llm_adapter`.

### Q-ARCH-3: `customer_context.md` write capability — **NOT in v0.1**

Read-only in v0.1 (used for routing context: authorization profile / change windows / compliance focus). Writes deferred to **Supervisor v0.2** with explicit operator approval gate — the only Supervisor capability for writing customer state is the v0.2 surface that needs the deepest review.

### Q-ARCH-4: routing-engine substrate hoist — **NOT in v0.1**

Same pattern as A.4 Q-ARCH-3. `routing/router.py` lives under `packages/agents/supervisor/src/supervisor/routing/`, NOT under `packages/shared/` or `packages/charter/`. Per ADR-007's 3rd-consumer hoist rule. If a future agent ever needs declarative routing primitives, hoist at that point with a one-paragraph rationale in the hoist PR.

---

## Q4 — eval-runner identity + 15 routing-test cases

**Supervisor IS registered as a `nexus_eval_runners` entry point.** Eval cases test **routing decisions**, not OCSF outputs — the first eval-runner divergence from the existing 16-agent pattern. The `actuals` dict carries `routing_decision` + `delegation_contract_shape` + `audit_actions_observed` instead of `findings_count` / `pass_rate` / etc.

A.4's batch eval picks up Supervisor automatically once the entry-point is registered → **17/17 agents covered by A.4 batch-eval at close.**

**15 cases:**

- **10 happy-path-per-specialist cases** (one per existing v0.1 specialist): cloud_posture / vulnerability / identity / runtime_threat / audit / investigation / network_threat / multi_cloud_posture / k8s_posture / remediation. Each: input task explicitly declares `target_agent=<specialist>` → assert `decision.target_agent == <specialist>` + delegation_contract shape matches.
- **5 edge-case cases**:
  - `no_target_agent_declared_pattern_match` — task carries `delta_type` only → routing-rule shape match wins.
  - `ambiguous_routing_multiple_matches` — two rules match → `Ambiguous` terminal → escalate.
  - `forbidden_target_agent` — task tries to route to an agent not in the registry → `NoMatch` terminal → escalate.
  - `over_capacity_5_parallel_tasks_cap` — 6 declared sub-tasks → 5 dispatched in parallel, 6th queued behind the semaphore (verifies cap=5 boundary).
  - `escalation_on_budget_exceeded` — synthetic specialist times out → partial result + `supervisor.escalation.raised` audit entry.

Each YAML case: `input_task` (the incoming ExecutionContract envelope) + `expected_target_agent` + `expected_delegation_contract` fields + `expected_audit_actions` array.

---

## Architecture

Five-stage pipeline + outer heartbeat loop (one fewer pipeline stage than A.4 — Supervisor has no DELTA stage since v0.1 is stateless):

```
                        ┌──────────────────────────────────────┐
                        │ Heartbeat loop (every 60s)           │
                        │ (single-threaded per customer via    │
                        │  fcntl.flock on customer_id.lock)    │
                        └─────────┬────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ Supervisor 5-stage pipeline (agent.run, per tick)                │
│                                                                  │
│  1. INGEST     — read triggers: events.> bus / CLI /             │
│                  scheduled queue file (metadata only).           │
│  2. ROUTE      — pure-function rule engine against               │
│                  agents.md → RoutingDecision[].                  │
│  3. DISPATCH   — parallel dispatch (Semaphore=5);                │
│                  in-process specialist invocation;               │
│                  F.1 budget-enforced; one attempt each.          │
│  4. AUDIT      — F.6 chain entries for each phase                │
│                  (heartbeat.started / .dispatched /              │
│                  .completed / .escalation.raised).               │
│  5. HANDOFF    — supervisor_report.md + per-escalation           │
│                  notification markdown.                          │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack.** Python 3.12 · BSL 1.1 · `charter.contract` (ExecutionContract for delegations) · `charter.audit` (F.6 chain) · `shared.fabric` (events.> subscriber if available — see drift item #1 / assumption flag below) · pydantic 2.9 · click 8 · file-backed queue via `json` + `os.rename` for atomicity · `fcntl.flock` for per-customer lock.

**Depends on:** all 16 prior v0.1 agents existing (now true).

**Assumption flag — F.7 v0.2 events.> bus.** The Supervisor v0.1 design assumes F.7 v0.2's `events.>` subscriber substrate has shipped. **Task 1 explicitly probes this** — if `shared.fabric.events_subject` is not available, Supervisor v0.1 falls back to operator-CLI + scheduled-queue triggers only (`events.>` integration becomes Supervisor v0.1.1 follow-up). The fallback is viable but degraded.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---- | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework). py.typed + `__init__`. Smoke tests including: 4 Q-ARCH deferral guards (no `claims_subject`/`CLAIMS_STREAM` import; no NLAH-write; no LLM in routing; no A.4 introspection coupling) + F.7 v0.2 events.> availability probe + standard charter import probes. **~13 smoke tests.**                                                                      |
| 2    | ⬜     |        | `schemas.py` — pydantic: `IncomingTask` / `RoutingRule` / `RoutingDecision` (Match/NoMatch/Ambiguous/Escalate variants) / `DelegationContract` / `DelegationOutcome` / `EscalationNotice` / `SupervisorReport`. **~18 schema tests** covering pydantic validation + variant invariants.                                                                                                                                             |
| 3    | ⬜     |        | `routing/parser.py` + `routing/agents.md` — markdown-with-frontmatter loader. Initial `agents.md` ships 10 happy-path rules (one per existing specialist) + permitted_tools per rule (per Q-ARCH-2 resolution). **~12 tests** including malformed YAML / missing required keys / unknown target_agent.                                                                                                                              |
| 4    | ⬜     |        | `routing/router.py` — pure-function rule engine. Takes `IncomingTask` + `RoutingRule[]`, returns `RoutingDecision`. Match precedence: explicit `target_agent_declared` > `task_type` pattern > `delta_type` pattern. Multiple matches → `Ambiguous`. **~14 tests** covering each variant + precedence ordering + escalate terminals.                                                                                                |
| 5    | ⬜     |        | `dispatch.py` — parallel dispatch with `asyncio.Semaphore(5)`. In-process specialist invocation via `nexus_eval_runners` entry-point lookup. Per-delegation try/except wrap → `DelegationOutcome` with status field. **~13 tests** including cap=5 boundary + per-delegation timeout + per-delegation raise tolerated.                                                                                                              |
| 6    | ⬜     |        | `escalation.py` — `EscalationNotice` builder + workspace markdown helper (`<workspace_root>/escalation_<run_id>.md`). No bus emission. **~8 tests** covering rule-engine `Escalate(reason)` terminal + budget-exceeded → escalation + escalation_id ULID uniqueness.                                                                                                                                                                |
| 7    | ⬜     |        | `scheduled_queue.py` — file-backed JSON queue at `<workspace_root>/.supervisor/scheduled/<customer_id>.json`. fcntl-locked appends + atomic-rename dequeue. **~10 tests** covering enqueue / dequeue / concurrent-append-via-lock / persisted-across-restart / missing-file-treated-as-empty.                                                                                                                                       |
| 8    | ⬜     |        | **SAFETY-CRITICAL — substrate touch.** Add `_FORBIDDEN_SUBSCRIPTIONS["supervisor"] = frozenset({"claims.>"})` to `packages/shared/src/shared/fabric/client.py`. Doc-only amendment to ADR-012 §"Subscriber ACL". `test_forbidden_subscription_supervisor.py` asserts the registry entry + that JetStreamClient rejects `claims.>` subscription from agent_id="supervisor". **NO auto-merge; verified-against-HEAD; manual review.** |
| 9    | ⬜     |        | `audit_emit.py` — 4 additive audit-action helpers (`heartbeat.started` / `delegation.dispatched` / `delegation.completed` / `escalation.raised`) wrapping `charter.audit.AuditLog.append`. **~10 tests** covering each entry shape + hash-chain preservation + customer_id propagation.                                                                                                                                             |
| 10   | ⬜     |        | `heartbeat.py` (outer 60s loop + fcntl per-customer lock + injectable `tick_interval_seconds` for tests) + `agent.py` (5-stage driver). Signature: `run(*, customer_id, workspace_root, semantic_store=None, scheduled_queue=None, ...) -> SupervisorReport`. **~16 tests** covering tick cadence + lock contention + INGEST→ROUTE→DISPATCH→AUDIT→HANDOFF flow + zero-trigger tick produces empty report.                           |
| 11   | ⬜     |        | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance — Supervisor is the **13th** agent shipped natively against v1.2 (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / D.6 / D.13 / D.12 / A.4 / **Supervisor**). README ("Supervisor persona") + tools.md + 3 examples (basic-routing / parallel-dispatch / escalation-on-timeout). **~17 tests.**                                                          |
| 12   | ⬜     |        | 15 representative YAML routing-test cases + `SupervisorEvalRunner` registered via `nexus_eval_runners`. Cases: 10 happy-path-per-specialist + 5 edge-cases (no-target / ambiguous / forbidden / over-capacity / escalation-on-budget). **~18 tests.**                                                                                                                                                                               |
| 13   | ⬜     |        | CLI (`supervisor run --customer-id ID` / `supervisor heartbeat-once` / `supervisor schedule TASK_JSON` / `supervisor eval`). 4 subcommands. **~16 CLI tests** using Click's CliRunner.                                                                                                                                                                                                                                              |
| 14   | ⬜     |        | **Stub-LLM eval harness** — `eval/stub_responses/<case_id>/responses.json` per case (15 files; all empty arrays since routing is rule-based). WI-3 byte-equal across reruns probe (×15 cases). **~30 tests** (5 layout + 3 resolver + 15 byte-equal-probes + 15 sanity-still-passes minus deduplication).                                                                                                                           |
| 15   | ⬜     |        | README polish + 3-step smoke runbook. (a) Unit tests + gates / (b) Eval suite via `supervisor eval` → 15/15 / (c) Live heartbeat against scheduled-queue. Architecture diagram + ADR-007 + Q-ARCH-1/2/3/4 deferral section.                                                                                                                                                                                                         |
| 16   | ⬜     |        | Verification record (`docs/_meta/supervisor-v0-1-verification-2026-05-21.md`) — 16-task table, gate results, 15/15 eval acceptance, WI-1..WI-6 watch-item resolutions, **Q-ARCH-1 carry-forward to A.4 v0.2 inheritance (WI-5 forward-carry to 3-forbidden-subscriber trajectory)**, Path-B sequence advance (**17/17 agents at v0.1 — platform-complete-narrow-depth**).                                                           |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-006](../../_meta/decisions/ADR-006-llm-adapter.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-010](../../_meta/decisions/ADR-010-within-agent-version-extension.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) · [ADR-012](../../_meta/decisions/ADR-012-claims-subject-namespace.md).

---

## Resolved questions

| #        | Question                                | Resolution                                                                                                                                                                                     | Task               |
| -------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| Q1       | Output shape?                           | 2 + 1 directions: F.6 audit chain (4 actions) + workspace markdown (`supervisor_report.md`) + conditional escalation markdown. **NO bus emission; NO OCSF; NO NLAH writes.**                   | Tasks 6, 9, 10     |
| Q2       | Routing mechanism?                      | Declarative rule engine reading `routing/agents.md`. Pure-function `router.py`. **No LLM call anywhere in the routing path.**                                                                  | Tasks 3, 4         |
| Q3       | Fan-out concurrency?                    | `asyncio.Semaphore(5)` parallel dispatch of pre-declared independent tasks. **NOT planning** — Supervisor never decides which agents to invoke beyond declarative rule matching.               | Task 5             |
| Q4       | Time-boxing + escalation?               | F.1 charter budget enforcement; one attempt per delegation; on budget exceeded → accept partial + raise escalation (notify-not-retry).                                                         | Tasks 5, 6, 10     |
| Q5       | Tenancy + state model?                  | `semantic_store=None` opt-in default; file-backed scheduled-task queue; per-customer `fcntl.flock` distributed lock; stateless across heartbeats. **`customer_context.md` READ-ONLY in v0.1.** | Tasks 7, 10        |
| Q6       | Audit posture?                          | 4 additive F.6 audit-action vocabulary entries (`heartbeat.started` / `delegation.dispatched` / `delegation.completed` / `escalation.raised`). No existing audit-action strings touched.       | Task 9             |
| Q-ARCH-1 | `claims.>` subscription?                | **NO.** Supervisor added to `_FORBIDDEN_SUBSCRIPTIONS` registry in Task 8 (SAFETY-CRITICAL). ADR-012 docs amended. **WI-5 forward-carry**: A.4 v0.2 will add the third subscriber.             | Task 8             |
| Q-ARCH-2 | A.4 introspection coupling for routing? | **NO.** Routes via declarative `agents.md` only. v0.2 may add LLM-assisted routing with AgentManifest consumption.                                                                             | (deferred to v0.2) |
| Q-ARCH-3 | `customer_context.md` write capability? | **NOT in v0.1.** READ-ONLY. v0.2 plan MUST include explicit operator approval gate before re-introducing.                                                                                      | (deferred to v0.2) |
| Q-ARCH-4 | Routing-engine substrate hoist?         | **Package-local FIRST** per ADR-007 3rd-consumer rule. Hoist only when a 2nd consumer arrives.                                                                                                 | Task 4             |

---

## Out of scope — explicit version-named deferrals (8 items)

1. **NO LLM-driven routing.** Deferred to **Supervisor v0.2** (Q-ARCH-2; requires AgentManifest consumption from A.4).
2. **NO multi-agent planning.** Deferred to **Supervisor v0.3+** (post-v0.2 LLM routing; planning is the harder problem).
3. **NO `customer_context.md` writes.** Deferred to **Supervisor v0.2** with explicit operator approval gate (Q-ARCH-3).
4. **NO auto-retry on delegation failure.** Deferred to **Supervisor v0.2** with explicit retry-budget contract.
5. **NO cron scheduler.** File-backed queue only. Cron deferred to **Supervisor v0.2** (likely external scheduler integration).
6. **NO F.5 SemanticStore reads** (customer baseline / historical patterns / cross-run learning). Deferred to **Supervisor v0.2+**.
7. **NO subprocess specialist isolation.** In-process invocation only. Deferred to **Supervisor v0.2+** pending telemetry on what actually breaks.
8. **NO multi-tenant production.** Blocks on future `SET LOCAL $1` tenant-RLS substrate-fix.

---

## File map (target)

```
packages/agents/supervisor/
├── pyproject.toml                                # Task 1
├── README.md                                     # Tasks 1, 15
├── src/supervisor/
│   ├── __init__.py                               # Task 1
│   ├── py.typed                                  # Task 1
│   ├── schemas.py                                # Task 2
│   ├── routing/
│   │   ├── __init__.py                           # Task 3
│   │   ├── agents.md                             # Task 3 (the routing table)
│   │   ├── parser.py                             # Task 3
│   │   └── router.py                             # Task 4
│   ├── dispatch.py                               # Task 5
│   ├── escalation.py                             # Task 6
│   ├── scheduled_queue.py                        # Task 7
│   ├── audit_emit.py                             # Task 9
│   ├── heartbeat.py                              # Task 10
│   ├── agent.py                                  # Task 10 (5-stage driver)
│   ├── nlah_loader.py                            # Task 11 (21-LOC shim)
│   ├── nlah/                                     # Task 11
│   │   ├── README.md
│   │   ├── tools.md
│   │   └── examples/                             # 3 examples
│   ├── eval_runner.py                            # Task 12
│   └── cli.py                                    # Task 13
├── eval/
│   ├── cases/                                    # Task 12 (15 routing-test YAML cases)
│   └── stub_responses/                           # Task 14 (15 empty arrays — routing is rule-based)
└── tests/
    ├── test_smoke.py                             # Task 1 (incl. 4 Q-ARCH guards + events.> probe)
    ├── test_schemas.py                           # Task 2
    ├── test_routing_parser.py                    # Task 3
    ├── test_routing_router.py                    # Task 4
    ├── test_dispatch.py                          # Task 5
    ├── test_escalation.py                        # Task 6
    ├── test_scheduled_queue.py                   # Task 7
    ├── test_forbidden_subscription_supervisor.py # Task 8 (SAFETY-CRITICAL)
    ├── test_audit_emit.py                        # Task 9
    ├── test_heartbeat.py                         # Task 10
    ├── test_agent_unit.py                        # Task 10
    ├── test_nlah_loader.py                       # Task 11
    ├── test_eval_runner.py                       # Task 12
    ├── test_cli.py                               # Task 13
    └── test_stub_harness.py                      # Task 14 (WI-3 byte-equal probe ×15)
```

---

## Risks

| Risk                                                                                          | Mitigation                                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `F.7` v0.2 `events.>` bus substrate not yet shipped → INGEST stage has no bus trigger         | Task 1 smoke test probes `shared.fabric.events_subject` availability. If absent, Supervisor v0.1 falls back to operator-CLI + scheduled-queue triggers only. `events.>` integration becomes a Supervisor v0.1.1 follow-up. Documented in verification record §"Forward carries." |
| In-process specialist invocation propagates per-specialist crashes into Supervisor            | Each delegation wrapped in try/except → `DelegationOutcome(status="error", reason=...)`. Test `test_dispatch_per_delegation_raise_tolerated` is the regression probe. Subprocess isolation deferred to v0.2 once telemetry tells us which crashes actually matter.               |
| `Semaphore(5)` cap interacts badly with long-running specialist (e.g. F.3 cloud_posture scan) | F.1 charter budget enforcement (wall-clock budget) bounds every delegation. The semaphore cap protects against runaway concurrent dispatch — it does not extend per-delegation wall-clock. Operator can override `concurrency=N` via CLI flag for batch-eval scenarios.          |
| Routing rule drift (e.g. an agent removed but rule still references it)                       | `routing/parser.py` validates every rule's `target_agent` against the registered `nexus_eval_runners` entry-point set at load time. Unknown target → `ValueError` at parse, not runtime.                                                                                         |
| `fcntl.flock` not portable to Windows                                                         | Production target is Linux/macOS only (per existing CI matrix). Windows support deferred to v0.2+. Documented in README §"Platform support."                                                                                                                                     |
| Q-ARCH-1 carry-forward dropped (A.4 v0.2 author misses the third forbidden subscriber)        | WI-5 in Supervisor v0.1 verification record explicitly names the trajectory: A.1 + Supervisor (this v0.1) + A.4 v0.2+. The v0.2 plan template for A.4 inherits this watch-item. Same mechanism A.4 v0.1 used to flag WI-5 for itself.                                            |
| In-process invocation lets specialist mutate Supervisor's module globals                      | Standard test isolation discipline. Smoke test asserts each test runs Supervisor in a fresh `tmp_path` workspace + monkeypatched `entry_points`. Production deployments rely on process boundaries between Supervisor restarts.                                                  |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed except Task 8.** `git diff --stat packages/charter/ packages/shared/` empty across Tasks 1-7 + 9-16. The single Task 8 substrate diff is bounded to `_FORBIDDEN_SUBSCRIPTIONS` dict entry (~5 lines) + ADR-012 doc amend.
- **WI-2: Single-tenant default.** `semantic_store=None` throughout; no cross-tenant reads. Heartbeat per-customer-locked via `fcntl.flock`.
- **WI-3: Stub-LLM determinism.** Per-case `responses.json`; routing is rule-based (naturally deterministic). 15 cases × byte-equal-across-reruns probe.
- **WI-4: No NLAH writes + no OCSF payload reads.** Two integration tests:
  1. `Path.open` + `builtins.open` patched while `agent.run` executes — asserts every observed mode is read-only (reused pattern from A.4).
  2. Router never accesses any OCSF field beyond envelope routing-keys (assertion in `test_routing_router.py`).
- **WI-5: Forward-carry — three forbidden subscribers.** Verification record names A.1 + Supervisor (this v0.1) + A.4 v0.2+ verbatim. A.4 v0.2 plan author MUST add `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]` before any auto-acting code lands.
- **WI-6: No LLM + no A.4-introspection coupling in routing path.** Smoke test asserts `charter.llm_adapter` is not imported anywhere under `routing/` or `dispatch.py`, AND `meta_harness.tools.nlah_parser` is not imported anywhere in Supervisor source. Q-ARCH-2 carry-forward.

---

## Done definition

Supervisor v0.1 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/supervisor`.
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `supervisor eval` returns 15/15 (deterministic via stub-LLM harness).
- `supervisor heartbeat-once --customer-id smoke` against the live 16-agent fleet produces a `supervisor_report.md` with at least one routing decision recorded in the audit chain.
- A.4 batch-eval picks up Supervisor automatically → **17/17 agents covered** in the latest `meta-harness run` against the workspace.
- ADR-007 v1.1 + v1.2 + ADR-010 + ADR-011 + ADR-012 conformance verified end-to-end.
- README + 3-step smoke runbook reviewed.
- Supervisor v0.1 verification record committed at `docs/_meta/supervisor-v0-1-verification-2026-05-21.md`.
- **Watch-items WI-1 through WI-6 verified at close**, with WI-5 explicitly carrying the three-forbidden-subscriber trajectory forward to A.4 v0.2.

That closes the **seventh and final unbuilt agent** under the Path-B operating rule. **17/17 platform-complete-narrow-depth.** The second-pass v0.2 conversation opens with `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) as the reference.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off branches like `feat/supervisor-task-N-<scope>`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label on Tasks 1-7 + 9-16** — all changes scoped to `packages/agents/supervisor/`.
- **SAFETY-CRITICAL label on Task 8 only** — the `_FORBIDDEN_SUBSCRIPTIONS["supervisor"]` substrate touch + ADR-012 doc amend. **NO auto-merge; verified-against-HEAD; manual review.**
- **Report → review → merge → next task.** After each task PR opens, pause for review. Don't start the next task until the prior PR merges.
- **Verified-against-HEAD sentence** in every PR body.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010.

---

## Next plans queued (for context, per Path-B operating rule)

- **Supervisor v0.1** (this plan) — seventh and final unbuilt agent.

After Supervisor closes: **17/17 platform-complete-narrow-depth.** Second-pass v0.2 conversation opens (Hermes-pattern absorption + A.4 v0.2 + v0.2 across the shipped agents).

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-within-agent-version-extension.md). [A.4 Meta-Harness v0.1's verification record](../../_meta/a-4-meta-harness-v0-1-verification-2026-05-21.md) is the closest reference for cadence + verification-record shape, particularly the WI-5 carry-forward mechanism Supervisor v0.1 extends.
