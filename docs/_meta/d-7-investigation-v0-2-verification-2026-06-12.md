# investigation (D.7) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-12 · **Cycle 14 of 17** · **Maturity: Level 1 → Level 2 (infrastructure).**
Investigation — structured-LLM **Orchestrator-Workers** forensic correlation; the **largest
cycle** (24 tasks) and the **second LLM-heavy cycle**, inheriting the three LLM-agent invariants
the D.13 synthesis cycle established and adding **three NEW Orchestrator-Workers invariants** as a
fresh institutional template (for D.12 Curiosity and A.1 Remediation to inherit). The full-Charter

- ToolRegistry conformist (unlike supervisor/synthesis deviators) and the fleet's **sole OCSF 2005
  emitter**. Single comprehensive directive, self-merge cascade. Per the Cycle-10 protocol
  amendment, Tasks 1–23 all auto-merge on green CI; the cycle closes when this record merges; the
  operator audits in batches (next batch covers Cycles 13 + 14).

---

## §1. Cycle summary

Took investigation from package **`__version__` 0.1.0 → 0.2.0** (ADR-010): live fleet-evidence
collection across **13 source agents**, resilient LLM hypothesis synthesis (DeepSeek → Anthropic →
deterministic fallback) via `charter.llm_adapter`, a HARD live-LLM e2e gate, continuous
infrastructure, and **six code-level invariants** (3 inherited + 3 new) — all keeping the OCSF
2005 wire shape and the 10 stub eval cases byte-identical (WI-I5).

- **24 tasks, 24 PRs** (#556–#579). 11 milestones.
- **Tests:** investigation **411 passed** + 3 gated-live skips (the cycle added the fleet-evidence,
  invariant, continuous, sweep and live-e2e suites). Full repo **6831 passed, 70 skipped, 0
  failed**.
- **Substrate seal EMPTY all 24** — no charter/shared edit. **No charter hoist** (none expected at
  D.7 — the first hoist fired at D.2, Cycle 11).
- **Deviation profile PRESERVED:** D.7 is a **conformist**, not a deviator — full `Charter` wrap +
  populated `ToolRegistry` (5 worker tools via `ctx.call_tool`) + sole 2005 emission, all
  unchanged. The LLM is reached **only** via `charter.llm_adapter` (no per-agent `llm.py` — the
  resilience wrapper lives under `investigation/providers/`, so the `test_no_per_agent_llm_module`
  guard stays green, heeding the Cycle-13 lesson).

## §2. Task execution table

| #   | Task                                                | PR          |
| --- | --------------------------------------------------- | ----------- |
| 1   | Bootstrap (version + ADR-010 + deviation re-verify) | #556        |
| 2   | Fleet evidence reader (13 source agents)            | #557        |
| 3   | Evidence aggregation + dedup                        | #558        |
| 4   | Substrate query (tenant-scoped, depth-capped)       | #559        |
| 5   | Fallback LLM provider abstraction                   | #560        |
| 6   | Investigation cost tracking                         | #561        |
| 7   | Sub-investigation: timeline enrichment              | #562        |
| 8   | Sub-investigation: attribution scoring              | #563        |
| 9   | Sub-investigation: spawn-batch planning             | #564        |
| 10  | Resilient hypothesis synthesis support              | #565        |
| 11  | Hypothesis evidence-refs filter (H3 drop)           | #566        |
| 12  | Containment plan (advisory-only, no enforcement)    | #567        |
| 13  | Report artifacts (plan.md + cost section)           | #568        |
| 14  | assert_categorical_only (WI-I8, inherited)          | #569        |
| 15  | assert_bounded_retry (WI-I10, inherited)            | #570        |
| 16  | assert_findings_cited (inherited) — closes M7       | #571        |
| 17  | assert_worker_bounded (WI-I11, NEW)                 | #572        |
| 18  | assert_evidence_chain (WI-I12, NEW)                 | #573        |
| 19  | assert_no_speculation (WI-I13, NEW) — closes M8     | #574        |
| 20  | Continuous scheduler infra (WI-I9)                  | #575        |
| 21  | Heartbeat + continuous coexistence — closes M9      | #576        |
| 22  | WI-I4 HARD live LLM e2e                             | #577        |
| 23  | 2005 sweep + coverage + runbooks + README v0.2      | #578        |
| 24  | Verification record + cycle closure                 | #579 (this) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                              | Where honored                                          |
| --- | ------------------------------------------------- | ------------------------------------------------------ |
| Q1  | (A) Orchestrator-Workers, depth ≤ 3, parallel ≤ 5 | `orchestrator_bounds.assert_worker_bounded` (Task 17)  |
| Q2  | (A) 6-stage pipeline preserved; OCSF 2005 sole    | unchanged; `schemas.OCSF_CLASS_UID == 2005`            |
| Q3  | (B) 13-source live fleet-evidence consumption     | `tools/fleet_evidence_reader` + `evidence_aggregation` |
| Q4  | (A) categorical-only privacy contract             | `privacy.categorical` (Task 14, WI-I8)                 |
| Q5  | (B) DeepSeek primary + Anthropic + deterministic  | `providers/` (Tasks 5-6, 10); scoreboard v0.3          |
| Q6  | (B) continuous + heartbeat coexistence            | `continuous/` (Tasks 20-21); INFRASTRUCTURE            |
| Q7  | (A) advisory-only containment, no enforcement     | `containment/plan` (Task 12, WI-I14)                   |

## §4. Gates passed

- **All 5 CI checks green** on every self-merged PR.
- **Substrate seal EMPTY** all 24; no charter/shared edit; no charter hoist.
- **OCSF 2005 byte-identical / stub eval byte-identical (WI-I5):** every new module is additive
  under `investigation/` subpackages — the v0.1 readers/schemas/orchestrator are untouched, so the
  10 stub eval cases pass identically (verified by the full investigation suite green each task).
- **Tenant-scoping (WI-I16/H6):** every store/workspace read carries a non-empty `tenant_id`;
  `read_fleet_evidence` + the scheduler reject an empty tenant.
- **Sub-agent allowlist preserved (WI-I15):** `SUB_AGENT_ALLOWLIST == frozenset({"investigation"})`
  — bootstrap-asserted + re-asserted in the live e2e after a real run.
- **Advisory-only (WI-I14):** the containment module has **no enforcement surface** (test-guarded);
  `build_a1_handoff` returns `{advisory: True, enforced: False, …}`. A.1 auto-dispatch is v0.3.
- **The six code-level invariants — 3 inherited + 3 NEW (the cycle's institutional contribution):**
  inherited `assert_categorical_only` (WI-I8) · `assert_bounded_retry` (WI-I10) ·
  `assert_findings_cited`; **NEW** `assert_worker_bounded` (WI-I11 — H5 depth/parallel caps) ·
  `assert_evidence_chain` (WI-I12 — malformed-or-dangling links) · `assert_no_speculation` (WI-I13
  — the zero-evidence floor). All exercised end-to-end (Task 22).
- **WI-I4 (HARD) e2e** green-shape: full 6-stage pipeline against a real provider, asserting OCSF
  2005 + 4 artifacts + tenant isolation + allowlist/caps unchanged + every hypothesis surviving all
  six invariants. Gated-live skipped in CI.
- **Cross-agent sweep (Task 23):** D.7 is the **sole OCSF 2005 emitter**, consuming the 13 source
  agents' 2002/2003/2004/6003 findings.
- **ruff + ruff format + mypy strict** clean per task.

## §5. Honest findings (WI-I3)

- **v0.2 is BREADTH, not new reasoning depth.** Multi-source consumption + the six-invariant set +
  the live-LLM proof are complete — but the **effective-permissions / Bayesian hypothesis-ranking
  depth is unchanged** (report confidence is still a naive mean). Deeper hypothesis reasoning is
  v0.3.
- **Continuous investigation is INFRASTRUCTURE; the production loop is NOT wired (Phase C, not
  v0.3).** The scheduler decides _when_ a tenant is due; it does not drive `agent.run()`. Wiring it
  — plus event-driven re-investigation on findings delta — is the **Phase C consolidated retrofit**
  after all 17 v0.2 cycles, explicitly NOT a v0.3 carry-forward.
- **Target was ~70%; realistic realized ~55-60% `[estimate]`.** The 13-source consumption +
  provider fallback + the invariant set + live-LLM proof are complete, but the production loop +
  deeper ranking are deferred, so realized capability sits below the headline target.
- **Per-source coverage (WI-I3, no aggregate):** the 13 sources consumed at ~55-60% `[estimate]`
  each (evidence read + timeline merge + per-finding hypothesis enumeration).
- **Deferred (v0.3):** Bayesian hypothesis ranking · effective-permissions-aware attribution ·
  A.1 auto-dispatch of the containment bundle · multi-provider scoreboard beyond DeepSeek+Anthropic
  · per-tenant LLM cost optimization.

## §6. Watch-items carry-forward

- The **Phase C wiring list** grows by one agent (investigation continuous → run()) — now 10 with
  the production-loop gap.
- Bayesian ranking + effective-permissions attribution + A.1 auto-dispatch (v0.3).
- **The three NEW Orchestrator-Workers invariants are now an institutional template** — D.12
  Curiosity (Cycle 15) and A.1 Remediation (Cycle 16) must inherit `assert_worker_bounded` +
  `assert_evidence_chain` + `assert_no_speculation` alongside the D.13 LLM-agent trio.

## §7. Phase C deferred handoff (NOT v0.3)

Wire the continuous investigation loop (scheduler-driven re-investigation + event-driven
re-correlation on findings delta) into `agent.run()` with the real DeepSeek/Anthropic provider —
the consolidated production-loop retrofit shared with the 9 prior cycles, after all 17 v0.2 cycles
close.

## §8. Cross-references

- Cross-agent sweep + per-source coverage: `packages/agents/investigation/tests/test_fleet_coverage_sweep.py`
- Runbooks: `packages/agents/investigation/runbooks/{investigation_workflow,continuous_monitoring,live_llm_setup,invariants_reference}.md`
- Code-level invariant lineage: D.3 `assert_authorized` · D.4 `assert_block_authorized` ·
  data-security `assert_privacy_contract` · F.6 `assert_audit_readonly` +
  `assert_admin_for_cross_tenant` · supervisor `assert_no_peer_to_peer` + `assert_signed_contract`
  · synthesis `assert_categorical_only` + `assert_bounded_retry` + `assert_findings_cited` (the
  LLM-agent template) · **investigation `assert_worker_bounded` + `assert_evidence_chain` +
  `assert_no_speculation` (the Orchestrator-Workers template)**.
- synthesis #555 (Cycle 13 LLM-agent precedent) · supervisor #535 (Cycle 12 precedent).

---

**investigation (D.7) v0.2 — CYCLE CLOSED ✅** (auto-merges on green CI per the Cycle-10 protocol).
24/24 tasks, 11/11 milestones, substrate seal empty throughout, deviation/conformist profile +
OCSF 2005 + stub eval byte-identity preserved, 0 failures. The largest cycle and second LLM-heavy
agent: 13-source fleet consumption + resilient synthesis + the **six code-level invariants**, with
the **three NEW Orchestrator-Workers invariants** established as the institutional template for
D.12 / A.1. Fleet now **14 of 17** agents at v0.2.
