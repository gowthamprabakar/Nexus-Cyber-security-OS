# Supervisor (#0) v0.1 — Verification Record

**Date closed:** 2026-05-21
**Plan:** [docs/superpowers/plans/2026-05-21-supervisor-v0-1.md](../superpowers/plans/2026-05-21-supervisor-v0-1.md)
**Status:** **CLOSED — 16/16 tasks merged.** Supervisor is **the 17th and FINAL agent at v0.1** under [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md), the **13th** shipped natively against ADR-007 v1.2's 21-LOC NLAH-loader shim, and the **seventh and last of 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md).

**This record closes the breadth-first push at 17/17 platform-complete-narrow-depth.** The second-pass v0.2 conversation opens at the next session.

## Execution status (16/16)

| Task | Status | Commit    | PR        | Notes                                                                                                                                                                                                                           |
| ---- | ------ | --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | ✅     | 9f47cb8   | #158      | Plan doc landed on main; 358 lines.                                                                                                                                                                                             |
| 1    | ✅     | ab0f944   | #159      | Bootstrap package — pyproject + `__init__` + 13 smoke tests incl. 4 Q-ARCH deferral guards + F.7 events.> availability probe (passes — no v0.1.1 fallback needed).                                                              |
| 2    | ✅     | 4dcf58f   | #160      | `schemas.py` — 8 pydantic types (IncomingTask / RoutingRule / RoutingDecision tagged-union {Match/NoMatch/Ambiguous/Escalate} / DelegationContract / DelegationOutcome / EscalationNotice / SupervisorReport). 19 schema tests. |
| 3    | ✅     | 5061a72   | #161      | `routing/parser.py` + `routing/agents.md` — markdown-with-YAML-frontmatter loader + initial routing table covering 10 v0.1 specialists. 12 tests.                                                                               |
| 4    | ✅     | fb12a1e   | #162      | `routing/router.py` — pure-function rule engine (precedence: target_agent_declared > task_type > delta_type; priority breaks ties). 23 tests incl. 10 bundled-agents.md integration probes.                                     |
| 5    | ✅     | 0f36c42   | #163      | `dispatch.py` — `Semaphore(5)` parallel dispatch; per-delegation `asyncio.wait_for` budget enforcement; DI'd DelegationInvoker. 13 tests.                                                                                       |
| 6    | ✅     | db92103   | #164      | `escalation.py` — EscalationNotice builder + workspace markdown writer; ULID per call. 8 tests.                                                                                                                                 |
| 7    | ✅     | 6682bc1   | #165      | `scheduled_queue.py` — file-backed JSON queue at `<workspace_root>/.supervisor/scheduled/<customer_id>.json` with fcntl-locked atomic drain. 10 tests.                                                                          |
| 8    | ✅     | b5c6804   | #166      | **SAFETY-CRITICAL substrate touch.** Added `_FORBIDDEN_SUBSCRIPTIONS["supervisor"] = frozenset({"claims.>"})` + ADR-012 doc amend. Manual review. 7 tests.                                                                      |
| 9    | ✅     | 63489c7   | #167      | `audit_emit.py` — 4 additive F.6 audit-action vocabulary entries (heartbeat.started / .dispatched / .completed / .escalation.raised). 10 tests.                                                                                 |
| 10   | ✅     | f4e8634   | #168      | `agent.py` (5-stage driver) + `heartbeat.py` (60s outer loop with fcntl per-customer lock + injectable interval). 17 tests.                                                                                                     |
| 11   | ✅     | f8ef11d   | #169      | NLAH bundle (`nlah_loader.py` 26-LOC shim + README + tools.md + 3 examples). 18 tests.                                                                                                                                          |
| 12   | ✅     | 62b629f   | #170      | `eval_runner.py` + 15 routing-test YAML cases (10 happy-path-per-specialist + 5 edge-cases). Supervisor is the **17th and final** `nexus_eval_runners` entry. 22 tests; 15/15 cases PASS.                                       |
| 13   | ✅     | a0b321a   | #171      | CLI (4 subcommands: `eval` / `heartbeat-once` / `schedule` / `run`). 16 Click CliRunner tests.                                                                                                                                  |
| 14   | ✅     | f777fb6   | #172      | Stub-LLM harness — 15 stub_responses dirs + **WI-3 byte-equal-across-reruns probe** per case (×15). 38 tests.                                                                                                                   |
| 15   | ✅     | d731dee   | #173      | README polish — 3-step smoke runbook + Q-ARCH-1/2/3/4 deferral section + WI-1..WI-6 + 8 named v0.2+ deferrals.                                                                                                                  |
| 16   | ✅     | _this PR_ | _this PR_ | This verification record + **17/17 platform-complete-narrow-depth closure**.                                                                                                                                                    |

**Test surface at close:** 226 tests across 14 test modules. mypy --strict 0 errors across 14 source files. ruff check + ruff format --check clean.

## Eval suite acceptance

`supervisor eval` → **15/15 PASS**, deterministic via the stub-LLM harness (which ships empty `responses.json` files since Supervisor doesn't consume an LLM in v0.1). All 15 cases also pass the WI-3 byte-equal-across-reruns probe (`tests/test_stub_harness.py`).

| Case                               | Verifies                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| `01_route_cloud_posture`           | Explicit `target_agent=cloud_posture` matches the bundled rule.                |
| `02_route_vulnerability`           | Same for vulnerability.                                                        |
| `03_route_identity`                | Same for identity.                                                             |
| `04_route_runtime_threat`          | Same for runtime_threat.                                                       |
| `05_route_audit`                   | Same for audit.                                                                |
| `06_route_investigation`           | Same for investigation.                                                        |
| `07_route_network_threat`          | Same for network_threat.                                                       |
| `08_route_multi_cloud_posture`     | Same for multi_cloud_posture.                                                  |
| `09_route_k8s_posture`             | Same for k8s_posture.                                                          |
| `10_route_remediation`             | Same for remediation.                                                          |
| `11_no_target_agent_pattern_match` | Task with no `target_agent`; `delta_type` pattern-match fallback wins.         |
| `12_ambiguous_routing`             | Two rules at same priority → `Ambiguous` → escalate.                           |
| `13_forbidden_target_agent`        | Task targets non-existent agent → `NoMatch` → escalate.                        |
| `14_over_capacity_parallel_tasks`  | 6 triggers under `Semaphore(5)` → all 6 complete in two waves.                 |
| `15_escalation_on_budget_exceeded` | Invoker raises → `ERROR` outcome → escalation raised (canonical non-OK probe). |

## Acceptance criteria (plan §Q1-Q6 + Q-ARCH-1/2/3/4 + watch-items)

| Criterion                                                                                           | Verification                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** Output: 2 + 1 directions (F.6 audit + workspace md + conditional escalation md); NO bus     | `agent.run` Stage 4 emits four additive audit actions via `audit_emit.emit_*`; Stage 5 writes `supervisor_report.md` to `workspace_root` + per-escalation `escalation_<id>.md`. **No `claims.>` publish** anywhere — Q-ARCH-1 smoke source-grep guard is the regression probe.                                                                                                                                         |
| **Q2.** Routing mechanism: declarative rule engine, NOT LLM-driven                                  | `routing/parser.py` loads `agents.md` (markdown-with-YAML-frontmatter); `routing/router.py` is pure-function (precedence: `target_agent_declared` > `task_type_pattern` > `delta_type_pattern`; `priority` breaks ties; ties at same priority → `Ambiguous`). **No `charter.llm_adapter` / `LLMProvider` import** anywhere under `routing/` or `dispatch.py` — Q-ARCH-2 smoke guard.                                   |
| **Q3.** Fan-out: parallel dispatch of pre-declared independent tasks; cap=5                         | `dispatch.dispatch_parallel(contracts, *, invoker, concurrency=MAX_PARALLEL_DISPATCH)` runs all contracts under `asyncio.Semaphore(5)`. 6th dispatch waits behind the semaphore (verified by `test_sixth_dispatch_waits_behind_semaphore`). NOT multi-agent planning — caller pre-declares contracts.                                                                                                                  |
| **Q4.** Time-boxing + escalation: F.1 budget; one attempt; escalation = notify-not-retry            | Per-delegation `asyncio.wait_for(invoker(contract), timeout=contract.budget_wall_clock_sec)`. TimeoutError → `DelegationOutcome(status=TIMEOUT_PARTIAL)`. Any other exception → `DelegationOutcome(status=ERROR)`. `escalation.build_delegation_escalation` converts non-OK outcomes into `EscalationNotice`; `write_escalation_markdown` writes the operator notification. **No auto-retry anywhere.**                |
| **Q5.** Tenancy + state: `semantic_store=None` opt-in default; file-backed queue; per-customer lock | `agent.run`'s `semantic_store` defaults to `None` (carried in signature for v0.2 forward-compat; unused in v0.1 — stateless heartbeats). `scheduled_queue.{enqueue,drain,peek}` uses `fcntl.flock` on the per-customer JSON queue file. `Heartbeat._per_customer_lock()` acquires `fcntl.LOCK_EX` on `<workspace_root>/.supervisor/locks/<customer_id>.lock`. `customer_context.md` is READ-ONLY in v0.1 per Q-ARCH-3. |
| **Q6.** Audit posture: 4 additive F.6 audit-action vocabulary entries                               | `supervisor.heartbeat.started` / `.delegation.dispatched` / `.delegation.completed` / `.escalation.raised`. Exported as `SUPERVISOR_AUDIT_ACTIONS: frozenset[str]`. F.6 hash-chain semantics inherited unchanged. Verified by `test_hash_chain_preserved_across_multiple_emits`.                                                                                                                                       |
| **Q-ARCH-1.** `claims.>` subscription — Supervisor added to `_FORBIDDEN_SUBSCRIPTIONS`              | **Task 8 SAFETY-CRITICAL substrate touch.** `_FORBIDDEN_SUBSCRIPTIONS["supervisor"] = frozenset({"claims.>"})` lives in `packages/shared/src/shared/fabric/client.py`. ADR-012 §"Subscriber ACL" amended with Supervisor row + 3-subscriber trajectory. Verified by `test_forbidden_subscription_supervisor.py` (7 tests) + existing A.1 fence tests (3/3 still PASS).                                                 |
| **Q-ARCH-2.** No A.4 introspection coupling for routing                                             | Smoke test `test_qarch4_wi6_no_meta_harness_introspection_coupling` source-greps: no `meta_harness.tools.nlah_parser` import anywhere in supervisor source. Routing is declarative-only via `agents.md`. v0.2 may introduce LLM-assisted routing with AgentManifest consumption.                                                                                                                                       |
| **Q-ARCH-3.** `customer_context.md` writes — NOT in v0.1                                            | Smoke test `test_qarch3_readme_documents_read_only_customer_context` asserts the deferral is documented verbatim in `README.md`. Writes deferred to v0.2 with explicit operator approval gate.                                                                                                                                                                                                                         |
| **Q-ARCH-4.** Routing-engine substrate hoist — NOT in v0.1                                          | `routing/router.py` lives under `packages/agents/supervisor/src/supervisor/routing/`, NOT under `packages/shared/` or `packages/charter/`. Per ADR-007 3rd-consumer hoist rule. If a future agent ever needs declarative routing primitives, hoist with a one-paragraph rationale in the hoist PR.                                                                                                                     |
| **WI-1** Substrate sealed except Task 8                                                             | `git diff --stat packages/charter/ packages/shared/` across Tasks 1-7 + 9-16 = **empty**. The single Task 8 substrate diff is bounded to 9 lines added to `client.py` + 4 lines amended in ADR-012.                                                                                                                                                                                                                    |
| **WI-2** Single-tenant default                                                                      | `semantic_store=None` is the documented default. Heartbeat per-customer-locked via `fcntl.flock`. Verified by `test_heartbeat_tick_once_runs_one_tick` (lock file created at tick).                                                                                                                                                                                                                                    |
| **WI-3** Stub-LLM determinism                                                                       | Per-case `eval/stub_responses/<case_id>/responses.json` (15 files; all empty arrays since routing is rule-based). `test_wi3_byte_equal_across_reruns` parametrised over all 15 cases asserts byte-equal serialized RunOutcome across reruns. **15/15 pass the probe.**                                                                                                                                                 |
| **WI-4** No NLAH writes + no OCSF payload reads                                                     | Smoke test `test_qarch2_no_llm_in_routing_path` source-greps under `routing/` + `dispatch.py`. Router only inspects four envelope keys on `IncomingTask` (`target_agent` / `task_type` / `delta_type` / `priority`); never opens OCSF payload bodies.                                                                                                                                                                  |
| **WI-5** Forward-carry — three forbidden subscribers                                                | **Named verbatim here so the A.4 v0.2 plan author can't miss it:** _"A.4 v0.2 plan author MUST add `_FORBIDDEN_SUBSCRIPTIONS['meta_harness'] = frozenset({'claims.>'})` before any auto-acting code lands."_ Three forbidden subscribers eventually: A.1 (ADR-012 original) + Supervisor (this v0.1) + A.4 v0.2+. Documented in NLAH README's persona block + ADR-012 §"Subscriber ACL" + this verification record.    |
| **WI-6** No LLM + no A.4-introspection coupling in routing path                                     | Smoke source-grep guards in `test_smoke.py::{test_qarch2_no_llm_in_routing_path, test_qarch4_wi6_no_meta_harness_introspection_coupling}` enforce both at the test-suite layer. CI regression-proofs the invariant.                                                                                                                                                                                                    |

## ADR conformance

| ADR | Provision                                     | Verification                                                                                                                                                                                                                                                                                             |
| --- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 005 | Async tool-wrapper convention                 | `dispatch_parallel` + `agent.run` + `Heartbeat.run_forever` + `scheduled_queue.{enqueue,drain}` all async; no blocking I/O on the event loop.                                                                                                                                                            |
| 006 | LLM adapter                                   | Supervisor doesn't consume an LLM in v0.1. The anti-pattern guard asserts `supervisor.llm` doesn't exist + the routing path doesn't import `charter.llm_adapter`.                                                                                                                                        |
| 007 | Reference NLAH (v1.1 + v1.2)                  | **v1.1** — no per-agent `llm.py`; smoke test `test_no_per_agent_llm_module` asserts. **v1.2** — `nlah_loader.py` is a 26-LOC shim over `charter.nlah_loader` (under the 35-LOC budget; verified by `test_nlah_loader_under_loc_budget`). Supervisor is the **13th** agent shipped natively against v1.2. |
| 008 | Eval framework                                | `SupervisorEvalRunner` registered via `[project.entry-points."nexus_eval_runners"]` — the **17th and final** v0.1 entry. Bundled `eval/cases/*.yaml` parses via `load_cases`; `run_suite` orchestrates all 15. **A.4 batch-eval picks up Supervisor automatically.**                                     |
| 010 | Within-agent version extension                | Execution-status table above is the single source of truth for task-commit pinning; deferred features explicitly named in README §"Out of scope" + the 8 version-named deferrals. **4 additive audit-action vocabulary entries** per condition 4.                                                        |
| 011 | PR-flow + branch protection discipline        | One-task-one-PR for all 16 tasks; LOW-RISK label on 15 of 16 PRs; **SAFETY-CRITICAL label on Task 8 (PR #166) — the only non-LOW-RISK PR in v0.1.** Verified-against-HEAD line in every PR body; no `--no-verify` / `--no-gpg-sign` shortcuts. Task 8 merged after manual review.                        |
| 012 | `claims.>` subject namespace + subscriber ACL | **Supervisor v0.1 added to `_FORBIDDEN_SUBSCRIPTIONS` registry** (Task 8). ADR-012 §"Subscriber ACL" doc-amended with Supervisor row + 3-subscriber future trajectory. WI-5 carries forward to A.4 v0.2.                                                                                                 |

## Architecture notes for future maintainers

### The platform orchestrator

Supervisor is the **first agent a customer task touches** and the **only agent in the fleet whose v0.1 closes a breadth-first sequence**. Routing is declarative + rule-based by design — the entire architectural narrowness was deliberate to protect the v0.2 conversation from being pre-committed by v0.1 decisions. Every v0.2+ feature builds on v0.1's narrow surface: LLM-assisted routing reuses the rule precedence; multi-agent planning extends `RoutingDecision` to a sequence; auto-retry composes with `EscalationNotice`.

### Q-ARCH-1 is the load-bearing safety invariant

The substrate fence added in Task 8 is the most important architectural commitment in Supervisor v0.1. **It is the only SAFETY-CRITICAL PR in v0.1** and the only substrate touch. Without it, Supervisor could (by accident or by future code change) subscribe to `claims.>`, consume a hypothesis from D.12 Curiosity, route it as if it were a finding, and trigger A.1 Remediation's auto-execute path — laundering speculation into destructive action.

**The fence is intentionally redundant**: ADR-012 documented the rule at the architectural layer in May 2026; Task 8 enforces it at the substrate layer for Supervisor (mirroring the A.1 enforcement that shipped with ADR-012 originally). Three layers of defence + the WI-5 forward-carry to A.4 v0.2+ are the load-bearing safety mechanism for the entire platform.

### Single-tenant `semantic_store=None` posture + stateless heartbeats

Supervisor v0.1's CLI defaults to "produce workspace markdown + audit chain entries; no SemanticStore reads." This is consistent with every prior agent's posture (D.5 / D.6 / D.7 / D.8 / D.12 / D.13 / A.4 all default to `semantic_store=None`). Multi-tenant production blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan; Supervisor v0.2+ also blocks on the same plan for any cross-heartbeat state.

When the substrate-fix lands, Supervisor's driver gets a `--semantic-store-dsn` flag that wires a real instance for v0.2's customer-baseline + historical-pattern reads. Until then, every heartbeat tick is stateless — Supervisor decides purely from the incoming task envelope + the routing table.

### File-backed scheduled queue + fcntl.flock — Linux/macOS only

The per-customer queue + lock files use `fcntl.flock`, which is POSIX-only. Windows support deferred to v0.2+ pending an `msvcrt.locking`-based alternative. CI matrix is Linux + macOS for the foreseeable future; Windows deployment is not a v0.1 customer ask.

### The 17th eval-runner entry — A.4 batch-eval coverage at 17/17

A.4 Meta-Harness shipped with 16/17 agent coverage at v0.1 close. With Supervisor's `SupervisorEvalRunner` registered in `nexus_eval_runners`, **A.4 batch-eval now covers all 17 v0.1 agents.** The next `meta-harness run` against the workspace will pick up Supervisor automatically + include its routing-decision pass rate alongside every other agent's OCSF pass rate. The eval-runner divergence (Supervisor tests routing, others test OCSF) is structural; A.4's `pass_rate` is per-case binary, so the cross-runner aggregation works without changes.

## Forward carries to v0.2 conversation

The second-pass v0.2 conversation opens after this record lands. The following items are flagged for the v0.2 plan authors:

### A.4 v0.2 — three forbidden subscribers (WI-5)

**Named verbatim:** A.4 v0.2 plan MUST add `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})` to `packages/shared/src/shared/fabric/client.py` before any auto-acting code lands. ADR-012 §"Subscriber ACL" should be amended at the same time to show the third entry + close out the "future auto-acting agents" paragraph. This becomes the equivalent of Supervisor v0.1's Task 8 — a SAFETY-CRITICAL substrate PR with manual review.

### Supervisor v0.2 — 8 deferral fronts

Each of the 8 explicit v0.1 deferrals (LLM-driven routing / multi-agent planning / customer_context.md writes / auto-retry / cron / F.5 reads / subprocess isolation / multi-tenant) is a candidate v0.2 surface. The plan author should re-evaluate which surface the design-partner signal supports + sequence them by safety risk. Recommended ordering: customer_context.md writes (highest review surface) → LLM-driven routing (requires AgentManifest consumption) → auto-retry (requires retry-budget contract) → cron/F.5/subprocess/multi-tenant.

### Hermes-pattern absorption

The next-cycle reference doc `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) is the v0.2+ architectural compass. Supervisor v0.2 + A.4 v0.2 are the two agents most directly affected by the Hermes absorption (LLM-driven routing in Supervisor + skill creation + NLAH auto-deploy in A.4).

## Path-B sequence advance — **17/17 PLATFORM-COMPLETE-NARROW-DEPTH**

**The breadth-first push is complete.** Seven of 7 unbuilt agents shipped under the [Path-B-breadth-first operating rule](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md):

1. ✅ D.5 Data Security v0.1 (shipped 2026-05-20; PRs #56-#71)
2. ✅ D.8 Threat Intel v0.1 (shipped 2026-05-21; PRs #73-#88)
3. ✅ D.6 Compliance v0.1 (shipped 2026-05-21; PRs #89-#105)
4. ✅ D.13 Synthesis v0.1 (shipped 2026-05-21; PRs #106-#122)
5. ✅ D.12 Curiosity v0.1 (shipped 2026-05-21; PRs #124-#140; ADR-012 unblocker 2026-05-21)
6. ✅ A.4 Meta-Harness v0.1 (shipped 2026-05-21; PRs #141-#157)
7. ✅ **Supervisor (#0) v0.1 (shipped 2026-05-21; PRs #158-_this PR_)** — this record closes the loop.

**17 of 17 agents at v0.1.** The fleet:

| #   | Agent               | Class                                                                      |
| --- | ------------------- | -------------------------------------------------------------------------- |
| 1   | F.3 cloud_posture   | reference (Path-A)                                                         |
| 2   | D.1 vulnerability   | Path-A                                                                     |
| 3   | D.2 identity        | Path-A                                                                     |
| 4   | D.3 runtime_threat  | Path-A                                                                     |
| 5   | F.6 audit           | Path-A                                                                     |
| 6   | D.7 investigation   | Path-A                                                                     |
| 7   | D.4 network_threat  | Path-A                                                                     |
| 8   | multi_cloud_posture | Path-A                                                                     |
| 9   | k8s_posture         | Path-A                                                                     |
| 10  | A.1 remediation     | Path-A (first auto-acting + first ADR-012 forbidden subscriber)            |
| 11  | D.5 data_security   | Path-B #1                                                                  |
| 12  | D.8 threat_intel    | Path-B #2                                                                  |
| 13  | D.6 compliance      | Path-B #3                                                                  |
| 14  | D.13 synthesis      | Path-B #4                                                                  |
| 15  | D.12 curiosity      | Path-B #5 (first claims.> publisher)                                       |
| 16  | A.4 meta_harness    | Path-B #6 (first agent that reads other agents)                            |
| 17  | **Supervisor (#0)** | **Path-B #7 (platform orchestrator; second ADR-012 forbidden subscriber)** |

The second-pass v0.2 conversation opens at the next session, with `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) as the architectural compass and the **WI-5 forward-carry** as the load-bearing safety inheritance to A.4 v0.2.

## Closure

Supervisor (#0) v0.1 is **CLOSED**. The 16/16 task table above is the single source of truth. The WI-1..WI-6 watch-items are all green. The Task 8 SAFETY-CRITICAL substrate fence is in place + ADR-012 is amended. **17/17 platform-complete-narrow-depth.**

The v0.2 plan authors' job, when they pick this up:

1. Read `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) for the v0.2+ surface direction.
2. Honor the **WI-5 forward-carry verbatim** (A.4 v0.2's third forbidden subscriber).
3. Inherit the v0.1 primitives unchanged where possible; extend additively per ADR-010.
4. Re-evaluate Supervisor's 8 deferrals against v0.2 signal; sequence by safety risk.

**The breadth-first push is complete. The platform is platform-complete-narrow-depth at v0.1.**
