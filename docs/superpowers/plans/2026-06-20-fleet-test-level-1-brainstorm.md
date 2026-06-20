# Fleet Test Level 1 — Integration (wiring smoke) brainstorm

_2026-06-20 · v2 directive (#766) §2 · v2 meta-brainstorm · carries the closed-#765 recon forward · v0.2-style template_

## 1. What L1 is (and is NOT)

L1 is the **smoke** layer: does each `agent.run()` complete, write expected entities via its
kg_writer, emit valid OCSF, propagate `tenant_id`, keep the audit chain clean, isolate tenants, and
stay byte-identical offline? **20 agents × 1 wiring test** at
`packages/agents/<agent>/tests/integration/test_wiring.py` (§2.2).

**Critical v1→v2 difference:** L1 does **NOT** assert "detection found the seeded violation" — that
was the v1 hide-and-seek mistake; capability (precision/recall/FP) is **L2**. L1 only proves the
plumbing. The seven §2.3 assertions, no more.

## 2. The 20-agent matrix (carried from #765, verified vs main)

| Agent               | kg_writer            | OCSF (findings.json)              | `run()` store shape         | L1 tier         |
| ------------------- | -------------------- | --------------------------------- | --------------------------- | --------------- |
| vulnerability       | yes                  | 2002                              | kwarg                       | A               |
| cloud-posture       | yes (`tools/`)       | 2003                              | kwarg                       | A               |
| multi-cloud-posture | yes (`tools/`, #764) | 2003                              | kwarg                       | A               |
| k8s-posture         | yes                  | 2003                              | kwarg                       | A               |
| data-security       | yes                  | 2003                              | kwarg                       | A               |
| identity            | yes                  | 2003, 2004                        | kwarg                       | A               |
| threat-intel        | yes                  | 2003                              | kwarg                       | A               |
| sspm                | yes                  | 2003                              | kwarg                       | A               |
| aispm               | yes                  | 2003, 2004                        | kwarg                       | A               |
| runtime-threat      | yes                  | 2004                              | kwarg                       | A               |
| network-threat      | yes                  | 2004                              | kwarg                       | A               |
| appsec              | yes                  | 2003                              | kwarg                       | A               |
| curiosity           | yes                  | 2004                              | kwarg                       | A               |
| synthesis           | yes                  | 2004                              | kwarg (+`llm_provider` req) | A               |
| compliance          | **no**               | 2003                              | kwarg                       | B read-only     |
| investigation       | **no** (reads graph) | 2005                              | positional, required        | B read-only     |
| remediation         | **no**               | 2007 (action)                     | none                        | B action        |
| audit               | **no**               | 6003 (via F.6, not findings.json) | `audit_store`               | B orchestration |
| supervisor          | **no**               | none                              | none (dispatcher)           | B orchestration |
| meta-harness        | yes (scorecards)     | none (findings.json)              | kwarg (diff shape)          | B orchestration |

14 Tier A · 2 Tier B read-only · 1 Tier B action · 3 Tier B orchestration = 20.

## 3. Per-tier L1 assertions (no fake-greens — swiss-bar #5/#12)

| Tier                | Assertions                                                                                                                                                                                                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**               | all 7 §2.3: run-completes · OCSF valid (declared class) · kg_writer ≥1 expected entity · `tenant_id` on every entity · audit chain hash-verifies · two-tenant disjoint · inert-offline byte-identical                                                                                     |
| **B read-only**     | all 7 **minus** kg_writer-wrote-entity (documented: reads graph / no writer). compliance: still assert OCSF 2003. investigation: assert OCSF 2005 **and** that it _reads_ the seeded graph (a read smoke, not a write)                                                                    |
| **B action**        | run-completes · OCSF **action** emission shape (2007) · `tenant_id` · audit chain · two-tenant disjoint · inert-offline. No kg_writer assertion (documented)                                                                                                                              |
| **B orchestration** | agent-specific, each documented: **supervisor** = routing-decision shape + audit + tenant (no OCSF/graph); **audit** = 6003 via F.6 + chain hash-verify (no findings.json OCSF, no graph); **meta-harness** = kg_writer wrote a scorecard entity + tenant + audit (no findings.json OCSF) |

Every omission is written in the test docstring with its reason. No assertion silently absent.

## 4. `packages/integration/fleet_testkit/` — the L1 shared surface

A new minimal uv-workspace package (also the future home of L2's evaluator + L6's pure-breed test).
L1 surface only (L2 adds the P/R/FP evaluator later — not now):

- `in_memory_semantic_store()` — sqlite + `Base.metadata.create_all` fixture (the
  `test_semantic_store.py` / D.15-e2e pattern).
- `assert_ocsf_valid(envelope_or_dict, *, class_uid)` — `unwrap_ocsf` + structural invariants
  (class_uid correct, `finding_info.types[0]` discriminator, required fields). (L1-Q4: strictness.)
- `assert_entity_written(store, *, tenant_id, category)` — kg_writer wrote ≥1 of the expected
  ADR-018 `NodeCategory`.
- `assert_audit_chain(audit_path)` — load + hash-verify the F.6 chain.
- `assert_two_tenant_disjoint(store, tenant_a, tenant_b)` — no shared entity/edge ids.
- `assert_inert_offline(run_without_store)` — no store → no writes; findings byte-identical.

Each `test_wiring.py` seeds the agent's tool surface from its **existing live-lane fakes** (Q3 =
synthetic, reuse the fakes that already mirror real shapes), runs real `run(...)` with an injected
in-memory store, calls the tier's assertion subset.

## 5. Sequencing (Q9: L1 infra per-PR, cascade self-merge)

1. **Stand up `packages/integration` + `fleet_testkit` (L1 surface) + 2 reference harnesses** —
   **cloud-posture** (Tier A, 2003, spine writer) + **runtime-threat** (Tier A, 2004, push-feed).
   **Per-PR review** (the pattern everything else copies).
2. **Cascade the other 18** `test_wiring.py` — self-merge. A Tier-B agent is reviewed per-PR only
   if it extends the testkit surface (e.g. the audit/F.6 6003 helper).
3. L1 PASS (§2.5): all 20 green · 0 integration false-negatives · audit chain verifies across all
   20 · tenant isolation across all 20 → unblocks L2.

## 6. L1 Q-set

- **L1-Q1 — reference agents.** cloud-posture + runtime-threat to lock the pattern. _Rec: yes_ (two
  dominant Tier-A shapes: posture-feed + event-push).
- **L1-Q2 — Tier-B orchestration subsets.** Confirm §3: supervisor = routing-shape + audit (no
  OCSF/graph); audit = 6003-via-F.6 + chain (no findings.json OCSF); meta-harness = scorecard
  entity + audit (no OCSF). _Rec: as tabled._
- **L1-Q3 — `packages/integration` as a real workspace package now.** _Rec: yes_ — minimal
  package, `fleet_testkit` only; it's the directive's named home for L2 evaluator + L6 finale.
- **L1-Q4 — OCSF strictness.** Structural invariants via `unwrap_ocsf` (no OCSF JSON-schema
  validator exists in-repo). _Rec: structural for L1_; a full schema validator is v0.5 hardening.

## 7. Swiss bar

Directive §8 binding. L1-relevant: real `run()` path (no detection-logic mocking) · in-memory
backend is the documented aiosqlite path (not mock theater, #2) · tenant isolation in **every**
wiring test (#7) · no fake-green via silent skip (#5/#12) · each `test_wiring.py` is final form +
a CI gate (#9). FakeLLMProvider only where an agent's run path calls an LLM (synthesis, the LLM
agents); deterministic.

## 8. Non-goals (L1)

Capability/precision/recall (L2), correlation (L3), Hermes-loop quality (L4), pressure (L5),
pure-breed (L6). No real Postgres (L5/L6). No new agent refactors — Tier-B `run()` shapes stay as
they are; the harness adapts.

## 9. Open for operator

Confirm L1-Q1..Q4. On approval: PR1 = `packages/integration` + `fleet_testkit` + the 2 reference
`test_wiring.py` (per-PR); then cascade the other 18 (self-merge).
