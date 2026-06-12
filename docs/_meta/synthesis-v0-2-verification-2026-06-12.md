# synthesis (D.13) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-12 · **Cycle 13 of 17** · **Maturity: Level 1 → Level 2 (infrastructure).**
Synthesis — LLM-driven narrative synthesis; the **first LLM-heavy agent cycle** and the
**institutional template** for the LLM-agent cycles that follow (D.7 Investigation, D.12
Curiosity, A.4 Meta-Harness self-evolution). The empty-registry LLM-first deviator. Single
comprehensive directive, self-merge cascade. Per the Cycle-10 protocol amendment, Tasks 1–20 all
auto-merge on green CI; the cycle closes when this record merges; the operator audits in batches
(next batch after Cycle 14).

---

## §1. Cycle summary

Took synthesis from package **`__version__` 0.1.0 → 0.2.0** (ADR-010): OCSF 2004 emission, source
scope 3 → 12, DeepSeek + Anthropic provider resilience, a live-LLM eval lane, continuous
infrastructure, and **three new code-level LLM-agent invariants** — all keeping the offline
stub-LLM eval byte-identical (WI-Y5).

- **20 tasks, 20 PRs** (#536–#555). 9 milestones.
- **Tests:** synthesis **215 → 352 passed** (+137) + 2 gated-live skips. Full repo **6674 passed,
  69 skipped, 0 failed**.
- **Substrate seal EMPTY all 20** — no charter/shared edit. **No charter hoist** (none expected
  at D.13).
- **Deviation profile PRESERVED (WI-Y9):** `build_registry()` stays empty; the LLM is reached
  **only** via `charter.llm_adapter` (no per-agent `llm.py` — the resilience wrapper lives under
  `synthesis/providers/`, not `synthesis/llm/`, so the ADR-007 v1.1 guard stays green). Markdown
  artifacts preserved alongside OCSF (WI-Y12).

## §2. Task execution table

| #   | Task                                                | PR          |
| --- | --------------------------------------------------- | ----------- |
| 1   | Bootstrap (version + ADR-010 + deviation re-verify) | #536        |
| 2   | OCSF 2004 schema with narrative in unmapped slot    | #537        |
| 3   | Narrative-to-OCSF translator                        | #538        |
| 4   | OCSF emission flow integration                      | #539        |
| 5   | Fleet workspace reader (3 -> 12 sources)            | #540        |
| 6   | Per-source finding enumeration                      | #541        |
| 7   | Cross-source narrative orchestration                | #542        |
| 8   | LLM provider fallback abstraction                   | #543        |
| 9   | Fallback trigger logic                              | #544        |
| 10  | LLM call cost tracking                              | #545        |
| 11  | NEXUS_LIVE_SYNTHESIS lane                           | #546        |
| 12  | Stub-LLM eval continuity                            | #547        |
| 13  | Continuous synthesis scheduler                      | #548        |
| 14  | Heartbeat + continuous coexistence                  | #549        |
| 15  | assert_categorical_only (WI-Y8)                     | #550        |
| 16  | assert_bounded_retry (WI-Y10)                       | #551        |
| 17  | assert_findings_cited hallucination guard (WI-Y13)  | #552        |
| 18  | WI-Y4 HARD live LLM e2e                             | #553        |
| 19  | 5-emitter sweep + coverage + runbooks + README      | #554        |
| 20  | Verification record + cycle closure                 | #555 (this) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                       | Where honored                                        |
| --- | ------------------------------------------ | ---------------------------------------------------- |
| Q1  | (A) OCSF 2004 + narrative in unmapped slot | `ocsf/` (Tasks 2-4); markdown preserved (WI-Y12)     |
| Q2  | (A) 3-call pipeline preserved; no 4th call | unchanged; 4th call deferred v0.3                    |
| Q3  | (B) source scope 3 -> 12                   | `tools/fleet_*` + `cross_source` (Tasks 5-7)         |
| Q4  | (A) categorical-only privacy contract      | `privacy.categorical` (Task 15, WI-Y8)               |
| Q5  | (B) DeepSeek primary + Anthropic fallback  | `providers/` (Tasks 8-10); scoreboard v0.3           |
| Q6  | (B) stub byte-identical + live lane        | `eval_continuity` + `live_lane` (Tasks 11-12, WI-Y5) |
| Q7  | (B) continuous + heartbeat coexistence     | `continuous/` (Tasks 13-14); INFRASTRUCTURE          |

## §4. Gates passed

- **All 5 CI checks green** on every self-merged PR.
- **Substrate seal EMPTY** all 20; no charter/shared edit; no charter hoist.
- **OCSF 2004 byte-identical** / **stub eval byte-identical (WI-Y5):** OCSF emission is additive
  (`synthesis_finding.json` alongside the unchanged markdown), so the 10 stub eval cases pass
  identically — verified by the full synthesis suite green each task.
- **Deviation profile preserved (WI-Y9):** empty `build_registry()`, LLM via `charter.llm_adapter`
  only — bootstrap-asserted (the `test_no_per_agent_llm_module` guard caught + corrected an early
  `synthesis/llm/` namespace; the wrapper moved to `synthesis/providers/`).
- **The three LLM-agent code-level invariants (the cycle's institutional contribution):**
  `assert_categorical_only` (WI-Y8 — no plaintext PII in narrative); `assert_bounded_retry`
  (WI-Y10/H5 — max 1 retry); `assert_findings_cited` (WI-Y13 — the **hallucination guard**,
  catching fabricated finding ids). All exercised end-to-end (Task 18).
- **WI-Y4 (HARD) e2e** green: fleet read → enumeration → cross-source → narrative → OCSF 2004,
  with the three invariants + the DeepSeek→Anthropic fallback. Gated-live skipped in CI.
- **Cross-agent sweep (Task 19, WI-Y6):** **5 OCSF 2004 emitters** (D.2/D.3/D.4/D.8/D.13) + 5
  consumers, **3260 passed / 19 skipped / 0 failed**.
- **ruff + ruff format + mypy strict** clean per task.

## §5. Honest findings (WI-Y3)

- **Continuous synthesis is INFRASTRUCTURE; the production loop is NOT wired (Phase C, not
  v0.3).** The pipeline is e2e-tested through OCSF emission, but is not wired into the agent's
  continuous `run()` loop; "live dispatch" of the 3-call pipeline is gated/skipped in CI. Wiring
  it — plus event-driven re-narration — is the **Phase C consolidated retrofit** after all 17
  v0.2 cycles, explicitly NOT a v0.3 carry-forward.
- **Target was ~60%; realistic realized ~50-60% `[estimate]`.** OCSF emission + 12-source
  synthesis + provider fallback + the privacy/hallucination invariants are complete — but the 4th
  LLM call + the production loop are deferred, so realized capability sits around the target.
- **Per-source coverage (WI-Y1, no aggregate):** the 12 sources at ~55-60% `[estimate]` each.
- **Deferred (v0.3):** 4th LLM call for risk-prioritization (Q2) · follow-up question generation
  (Q2) · multi-provider scoreboard beyond DeepSeek+Anthropic (Q5) · per-tenant LLM cost
  optimization.
- **Process: the `reset --hard`-after-failed-commit trap recurred TWICE this cycle (Tasks 8 + 10)** — a commit header >100 chars (Task 8) and a body line >100 chars (Task 10) failed
  commitlint, and the chained reset wiped the new files (recreated both). Reinforced rule: keep
  commit **headers AND body lines ≤100 chars** (target ≤95), and verify `commit-exit=0` before
  any reset.

## §6. Watch-items carry-forward

- The **Phase C wiring list** grows by one agent (synthesis continuous → run()) — now 9 with the
  production-loop gap.
- The 4th LLM call + multi-provider scoreboard + follow-up generation (v0.3).
- **The three LLM-agent invariants are now the institutional template** — D.7 (Cycle 14), D.12
  (Cycle 15), and A.4 (v0.3 wave) must inherit `assert_categorical_only` +
  `assert_bounded_retry` + `assert_findings_cited`.

## §7. Phase C deferred handoff (NOT v0.3)

Wire the continuous synthesis loop (scheduler-driven re-narration + event-driven re-synthesis on
findings delta) into `agent.run()` with the real DeepSeek/Anthropic provider — the consolidated
production-loop retrofit shared with the 8 prior cycles, after all 17 v0.2 cycles close.

## §8. Cross-references

- Cross-agent sweep: `synthesis-v0-2-cross-agent-sweep-2026-06-12.md`
- Per-source coverage: `synthesis-v0-2-per-source-coverage-2026-06-12.md`
- Runbooks: `packages/agents/synthesis/runbooks/{llm_provider_config,live_llm_lane,stub_eval_harness,privacy_contract_testing}.md`
- Code-level invariant lineage: D.3 `assert_authorized` · D.4 `assert_block_authorized` ·
  data-security `assert_privacy_contract` · F.6 `assert_audit_readonly` +
  `assert_admin_for_cross_tenant` · supervisor `assert_no_peer_to_peer` + `assert_signed_contract`
  · **synthesis `assert_categorical_only` + `assert_bounded_retry` + `assert_findings_cited` (the
  LLM-agent template)**.
- supervisor #535 (Cycle 12 precedent) · audit #517 (cross-agent sweep precedent).

---

**synthesis (D.13) v0.2 — CYCLE CLOSED ✅** (auto-merges on green CI per the Cycle-10 protocol).
20/20 tasks, 9/9 milestones, substrate seal empty throughout, deviation profile + stub eval
byte-identity preserved, 0 failures. The first LLM-heavy cycle: OCSF 2004 emission + 12-source
synthesis + provider fallback, with the **three LLM-agent code-level invariants** established as
the institutional template for D.7 / D.12 / A.4.
