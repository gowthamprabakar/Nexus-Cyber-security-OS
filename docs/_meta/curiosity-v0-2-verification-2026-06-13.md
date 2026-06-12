# curiosity (D.12) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-13 · **Cycle 15 of 17** · **Maturity: Level 1 → Level 2 (infrastructure).**
Curiosity — proactive coverage-gap hypothesis emission; the **GENERATIVE counterpart to D.7**
(D.7 explains observed events; D.12 proposes what hasn't been looked at). The **second-to-last
v0.2 cycle** and the **third LLM-heavy** cycle — it closes the LLM-agent invariant inheritance
chain (D.13 → D.7 → D.12) and adds **three NEW curiosity-specific invariants**. The first
publisher on the `claims.>` substrate (ADR-012) and now the **6th OCSF 2004 emitter**. Single
comprehensive directive, self-merge cascade. Per the Cycle-10 amendment, Tasks 1–19 auto-merge on
green CI; the cycle closes when this record merges; the operator audits Cycles 13+14+15 in a batch.

---

## §1. Cycle summary

Took curiosity from package **`__version__` 0.1.0 → 0.2.0** (ADR-010): OCSF 2004 emission, source
scope 4 → 14, DeepSeek + Anthropic resilience, three coverage-gap kinds, six code-level
invariants, and continuous infrastructure — all keeping the CuriosityClaim envelope + the offline
stub-LLM eval byte-identical (WI-X5/X6).

- **20 tasks, 20 PRs** (#580–#599). 9 milestones.
- **Tests:** curiosity **334 passed** + 1 gated-live skip (the cycle added the OCSF, source,
  gap, provider, invariant, continuous, sweep and live-e2e suites). Full repo **6938 passed, 71
  skipped, 0 failed**.
- **Substrate seal EMPTY all 20** — no charter/shared edit. **No charter hoist** (none expected at
  D.12).
- **Deviation profile PRESERVED (WI-X12):** D.12 stays an LLM-only deviator — `build_registry()`
  stays empty; the LLM is reached **only** via `charter.llm`; the provider wrapper lives under
  `curiosity/providers/` and the H4 gate under `curiosity/gate/` (NOT `curiosity/llm/`), so the
  `test_no_per_agent_llm_module` guard stays green (the Cycle-13/14 lesson, applied proactively).

## §2. Task execution table

| #   | Task                                                  | PR          |
| --- | ----------------------------------------------------- | ----------- |
| 1   | Bootstrap (version + ADR-010 + deviation re-verify)   | #580        |
| 2   | OCSF 2004 schema for claim emission                   | #581        |
| 3   | Claim-to-OCSF translator                              | #582        |
| 4   | OCSF emission flow integration                        | #583        |
| 5   | Sibling state reader 4 -> 14 sources                  | #584        |
| 6   | Live SemanticStore aggregate reads                    | #585        |
| 7   | Per-tenant region-gap thresholds                      | #586        |
| 8   | Technique-gap detection (NEW)                         | #587        |
| 9   | Time-gap detection (NEW)                              | #588        |
| 10  | DeepSeek + Anthropic fallback provider                | #589        |
| 11  | LLM cost telemetry per scan window                    | #590        |
| 12  | assert_categorical_only (WI-X9, inherited)            | #591        |
| 13  | assert_bounded_retry (WI-X10, inherited)              | #592        |
| 14  | assert_coverage_gap_cited (WI-X11, inherited+adapted) | #593        |
| 15  | assert_tenant_scoped (WI-X13, NEW)                    | #594        |
| 16  | assert_no_claims_subscription (WI-X14, NEW)           | #595        |
| 17  | assert_llm_only_with_gaps (WI-X15, NEW)               | #596        |
| 18  | Continuous scheduler + mode coexistence               | #597        |
| 19  | Live e2e + 2004 sweep + runbooks + README v0.2        | #598        |
| 20  | Verification record + cycle closure                   | #599 (this) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                             | Where honored                                      |
| --- | ------------------------------------------------ | -------------------------------------------------- |
| Q1  | (A) OCSF 2004 + CuriosityClaim in unmapped slot  | `ocsf/` (Tasks 2-4); claims.> + markdown preserved |
| Q2  | (B) source scope 4 -> 14                         | `tools/source_agents` + reader (Tasks 5-6)         |
| Q3  | (B) DeepSeek primary + Anthropic fallback        | `providers/` (Tasks 10-11); scoreboard v0.3        |
| Q4  | (D) all 3 gap kinds (region + technique + time)  | `gaps/` (Tasks 7-9); WI-X1 tracked separately      |
| Q5  | (A) tenant-scoped always; cross-tenant forbidden | `tenant.scoped` (Task 15, WI-X13)                  |
| Q6  | (B) continuous + heartbeat coexistence           | `continuous/` (Task 18); INFRASTRUCTURE            |
| Q7  | (A+) single-publisher preserved; producer-only   | `claims.producer_only` (Task 16, WI-X14)           |

## §4. Gates passed

- **All 5 CI checks green** on every self-merged PR.
- **Substrate seal EMPTY** all 20; no charter/shared edit; no charter hoist.
- **OCSF 2004 byte-identical / stub eval byte-identical (WI-X5):** the OCSF emission is additive
  (`curiosity_findings.json` alongside the unchanged `hypotheses.md` + `probe_directives.json` +
  the claims.> publish), and the eval validates the returned report (not the artifact set), so the
  10 stub cases pass identically — verified by the full curiosity suite green each task.
- **CuriosityClaim byte-identical (WI-X6):** the translator is additive; the source claim is
  frozen + untouched, so claims.> consumers are unaffected.
- **Deviation profile preserved (WI-X12):** empty `build_registry()`, LLM via `charter.llm` only —
  bootstrap-asserted; the provider wrapper went to `providers/`, the H4 gate to `gate/`, so the
  `test_no_per_agent_llm_module` guard stayed green throughout.
- **The six code-level invariants — 3 inherited + 3 NEW (the cycle's institutional contribution):**
  inherited `assert_categorical_only` (WI-X9) · `assert_bounded_retry` (WI-X10) ·
  `assert_coverage_gap_cited` (WI-X11 — the generative-agent hallucination guard: a hypothesis must
  cite a _detected_ gap); **NEW** `assert_tenant_scoped` (WI-X13 — H5 privacy contract) ·
  `assert_no_claims_subscription` (WI-X14 — producer-only fence, mirroring supervisor) ·
  `assert_llm_only_with_gaps` (WI-X15 — H4 skip-LLM-when-no-gaps). All exercised end-to-end
  (Task 19).
- **WI-X4 (HARD) e2e** green-shape: full pipeline against a real provider, all six invariants +
  OCSF 2004 + tenant isolation + producer-only. Gated-live skipped in CI.
- **Cross-agent sweep (Task 19, WI-X7):** D.12 is the **6th OCSF 2004 emitter**
  (D.2/D.3/D.4/D.8/D.13/D.12); D.7's 2005 is distinct.
- **ruff + ruff format + mypy strict** clean per task.

## §5. Honest findings (WI-X3)

- **v0.2 is BREADTH, not depth.** OCSF emission + 14-source consumption + provider fallback + the
  six invariants are complete — but of the three new gap detectors, **only region remains the
  run-loop driver**; the technique-gap + time-gap detectors ship as **infrastructure** (pure,
  unit-tested, with their own `coverage_gap_id` namespaces) and are NOT yet wired into the DETECT
  stage (wiring them would change the run output + the stub eval). That wiring is Phase C / v0.3.
- **Continuous curiosity is INFRASTRUCTURE; the production loop is NOT wired (Phase C, not v0.3).**
  The scheduler decides _when_ a tenant is due; it does not drive `agent.run()`. Wiring it — plus
  event-driven re-scan on findings delta — is the **Phase C consolidated retrofit** after all 17
  v0.2 cycles, explicitly NOT a v0.3 carry-forward.
- **Target was ~60%; realistic realized ~50-60% `[estimate]`.** OCSF emission + multi-source + the
  invariant set are done; the technique/time run-loop wiring + the production loop are deferred, so
  realized capability sits around the lower bound of the target.
- **Per-source coverage (WI-X1, no aggregate):** the 14 sources at ~50-55% `[estimate]` each;
  per-gap-kind: region driven end-to-end, technique/time as infra only.
- **Deferred (v0.3):** technique/time gap wiring into DETECT · agent-coverage-gap detection (Q4) ·
  LLM-driven probe orchestration · multi-provider scoreboard beyond DeepSeek+Anthropic ·
  the `schema_version` consumer migration on claims.>. **Cross-tenant aggregation: NEVER** (WI-X13
  privacy contract).
- **Process:** the `reset --hard`-after-failed-commit trap recurred once (Task 16 — a RUF043 `.`
  metacharacter in a `pytest.raises(match=...)` failed husky's `ruff --fix`, and the chained reset
  wiped the new files; recreated with raw-string `match=` after verifying `ruff check` clean
  FIRST). Reinforced rule: run plain `ruff check` (no `--fix`) and confirm exit 0 before any
  commit+reset chain.

## §6. Watch-items carry-forward

- The **Phase C wiring list** grows by one agent (curiosity continuous → run()) — now 11 with the
  production-loop gap; plus the technique/time gap-detector DETECT wiring.
- The `schema_version` field on CuriosityClaim is additive now; consumer migration is v0.3.
- **The LLM-agent invariant chain is now PROVEN across 3 cycles** (D.13 → D.7 → D.12):
  categorical_only + bounded_retry + (findings_cited / evidence_chain / coverage_gap_cited).
- **The three NEW curiosity-specific invariants** (tenant_scoped + producer-only +
  llm_only_with_gaps) are available for any future generative agent.

## §7. Phase C deferred handoff (NOT v0.3)

Wire the continuous curiosity loop (scheduler-driven re-scan + event-driven re-scan on findings
delta) into `agent.run()` with the real DeepSeek/Anthropic provider, AND wire the technique-gap +
time-gap detectors into the DETECT stage — the consolidated production-loop retrofit shared with
the 10 prior cycles, after all 17 v0.2 cycles close.

## §8. Cross-references

- Cross-agent sweep + live e2e: `packages/agents/curiosity/tests/test_cross_agent_2004_sweep.py` +
  `tests/integration/test_curiosity_live_e2e.py`
- Runbooks: `packages/agents/curiosity/runbooks/{llm_provider_config,live_llm_lane,claims_producer_setup,coverage_gap_tuning,privacy_contract_testing}.md`
- Code-level invariant lineage: D.3 `assert_authorized` · D.4 `assert_block_authorized` ·
  data-security `assert_privacy_contract` · F.6 `assert_audit_readonly` +
  `assert_admin_for_cross_tenant` · supervisor `assert_no_peer_to_peer` + `assert_signed_contract`
  (+ the `_FORBIDDEN_SUBSCRIPTIONS` fence D.12 mirrors) · synthesis/D.7 the LLM-agent template ·
  **curiosity `assert_tenant_scoped` + `assert_no_claims_subscription` + `assert_llm_only_with_gaps`
  (the generative-agent set)**.
- synthesis #555 (Cycle 13 LLM-agent invariant source) · investigation #579 (Cycle 14 LLM-agent
  proof) · supervisor #535 (producer-only / fence pattern source).

---

**curiosity (D.12) v0.2 — CYCLE CLOSED ✅** (auto-merges on green CI per the Cycle-10 protocol).
20/20 tasks, 9/9 milestones, substrate seal empty throughout, deviation profile + CuriosityClaim +
stub eval byte-identity preserved, 0 failures. The third LLM-heavy cycle and the first generative
OCSF emitter: OCSF 2004 emission + 14-source consumption + 3 gap kinds, with the **six code-level
invariants** — the LLM-agent inheritance chain (D.13 → D.7 → D.12) closed and **three NEW
curiosity-specific invariants** established. Fleet now **15 of 17** agents at v0.2 (~88%). Only A.1
Remediation (Cycle 16, SAFETY-CRITICAL) remains.
