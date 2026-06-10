# NLAH Framework Full Backfill — Verification Record & Cycle Closure

**Status:** Cycle closure. Consolidates Milestone-4 Tasks 26 (compliance sweep), 27 (OCSF/cross-agent regression sweep), and 28 (verification record).
**Date:** 2026-06-10
**Cycle:** NLAH Framework Full Backfill (the standard-setting cycle)
**Audit that triggered it:** [nlah-framework-audit-2026-06-09.md](nlah-framework-audit-2026-06-09.md) (PR #316)

> This is the proof that the standard is met. After this lands, every agent is grade A against the
> [ADR-007 v1.7](decisions/ADR-007-cloud-posture-as-reference-agent.md) compliance checklist, the
> `permitted_tools` whitelist is a hard structural boundary, and forward drift is fenced by
> [ADR-017](decisions/ADR-017-v0-2-cycle-quality-gate.md).

---

## Section 1 — Cycle summary

The [NLAH framework audit (#316)](nlah-framework-audit-2026-06-09.md) found the five-layer NLAH standard
lived as _documented intent_, not enforced reality: `permitted_tools` was opt-in (three agents bypassed
it, one being the state-mutating remediation agent), the Layer-1 literal structure was used by no agent,
Layer-3 file artifacts by none, Layer-4 numeric thresholds by 2/17, and two v0.2 agents carried NLAH
scope statements that contradicted shipped code (S-4 drift).

The operator opened the Full Backfill cycle to make the standard **structural**. Across four milestones
and 28 tasks it: closed the tool-gating bypass _as a class_ (hard boundary), reconciled the spec to
as-built reality, codified the objective compliance bar + a per-cycle drift gate, brought all 17 agents
to grade A, and certified the result here.

**Outcome:** 17/17 agents grade A against ADR-007 v1.7. Tool-gating bypass is structurally impossible.
NLAH-vs-code drift is gated. The discipline is inherited by every future cycle.

---

## Section 2 — Task execution table

| #     | Milestone | Task                                                | PR          | Risk            |
| ----- | --------- | --------------------------------------------------- | ----------- | --------------- |
| 1     | M1        | ADR-016 tool-proxy hard-boundary design             | #317        | LOW-RISK        |
| 2     | M1        | Implement tool-proxy + `forbidden_tools` + CI guard | #318        | SAFETY-CRITICAL |
| 3     | M1        | C-1 remediation `apply_patch` gate                  | #319        | SAFETY-CRITICAL |
| 4     | M1        | C-2 vulnerability `is_kev`/`nvd_enrich` gate        | #320        | SAFETY-CRITICAL |
| 5     | M1        | C-3 investigation worker gate + `assert_complete`   | #321        | SAFETY-CRITICAL |
| 6     | M2        | Reconcile spec to as-built (§0)                     | #322        | LOW-RISK        |
| 7     | M2        | ADR-007 v1.7 universal compliance checklist         | #323        | LOW-RISK        |
| 8     | M2        | ADR-017 v0.2 cycle quality gate                     | #324        | LOW-RISK        |
| 9     | M3        | cloud-posture NLAH (reference template)             | #325        | LOW-RISK        |
| 10    | M3        | vulnerability NLAH (+ S-4 fix)                      | #326        | LOW-RISK        |
| 11    | M3        | multi-cloud-posture NLAH (+ S-4 fix)                | #327        | LOW-RISK        |
| 12    | M3        | identity NLAH                                       | #328        | LOW-RISK        |
| 13    | M3        | runtime-threat NLAH                                 | #329        | LOW-RISK        |
| 14    | M3        | network-threat NLAH                                 | #330        | LOW-RISK        |
| 15    | M3        | data-security NLAH                                  | #331        | LOW-RISK        |
| 16    | M3        | k8s-posture NLAH                                    | #332        | LOW-RISK        |
| 17    | M3        | compliance NLAH                                     | #333        | LOW-RISK        |
| 18    | M3        | threat-intel NLAH                                   | #334        | LOW-RISK        |
| 19    | M3        | remediation NLAH                                    | #335        | LOW-RISK        |
| 20    | M3        | investigation NLAH                                  | #336        | LOW-RISK        |
| 21    | M3        | audit NLAH (deviator)                               | #337        | LOW-RISK        |
| 22    | M3        | supervisor NLAH (deviator)                          | #338        | LOW-RISK        |
| 23    | M3        | curiosity NLAH (deviator)                           | #339        | LOW-RISK        |
| 24    | M3        | synthesis NLAH (deviator)                           | #340        | LOW-RISK        |
| 25    | M3        | meta-harness NLAH (deviator)                        | #341        | LOW-RISK        |
| 26–28 | M4        | Compliance sweep + OCSF regression + this record    | _(this PR)_ | LOW-RISK        |

---

## Section 3 — Audit findings → resolutions

| Finding                                                                          | Severity | Resolution                                                                                                                                  |
| -------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **C-1** remediation `apply_patch` (EXECUTE mutation) bypassed the charter        | HIGH     | #319 — routed through `ctx.call_tool`; pre-execute permitted-tools re-check; charter `tool_call` audit + retained `PipelineAuditor`.        |
| **C-2** vulnerability `is_kev`/`nvd_enrich` external calls unregistered + direct | MEDIUM   | #320 — registered + gated; `trivy_to_findings` refuses to enrich without a charter; registry pipeline threaded; `tools.md` corrected.       |
| **C-3** investigation worker tools direct + missing `assert_complete`            | LOW–MED  | #321 — 3 stateful tools gated inside the fan-out; `extract_iocs`/`map_to_mitre` reclassified pure (unregistered); `assert_complete` added.  |
| **Root cause** `permitted_tools` opt-in, not a choke point                       | —        | #317/#318 — tool-proxy hard boundary (`DirectInvocationBlocked`) + CI import guard. `permitted_tools` is now structurally enforced.         |
| **S-1** Layer-3 file schema unimplemented (0/17)                                 | Systemic | #322 — spec §0 reconciled to the as-built `audit.jsonl` + `ctx.write_output` mechanism; raw `reasoning_trace.md` documented as a v0.3 item. |
| **S-2** Layer-4 numeric thresholds (2/17)                                        | Systemic | M3 (#325–341) — every NLAH now carries numeric self-evolution thresholds.                                                                   |
| **S-3** Layer-5 pattern declarations undeclared                                  | Systemic | M3 (#325–341) — every NLAH now carries a formal Pattern declaration.                                                                        |
| **S-4** v0.2 NLAH scope/version drift                                            | Systemic | #326 (vulnerability registry scanning) + #327 (multi-cloud live SDK) corrected; **ADR-017 (#324)** gate prevents recurrence.                |
| **`forbidden_tools` absent from the contract schema**                            | —        | #318 — added (defense-in-depth) with a no-overlap validator.                                                                                |

---

## Section 4 — Charter substrate changes (M1)

The hard boundary ([ADR-016](decisions/ADR-016-tool-proxy-hard-boundary.md)) is in place:

- `ToolRegistry` wraps every registered tool in a `_ProxiedTool`; the underlying callable runs only inside
  a charter dispatch (a `ContextVar` set by `ToolRegistry.call`). Any other invocation raises
  `DirectInvocationBlocked` — covering sync **and** async tools, flag reset on exceptions.
- `ExecutionContract.forbidden_tools` (no-overlap validator); `Charter.call_tool` checks it first → `ToolForbidden`.
- `packages/charter/tests/test_tool_import_guard.py` statically forbids a registered tool callable being
  invoked in a driver module. `PENDING_MIGRATION` is now **empty** (all bypasses closed);
  `BY_DESIGN_EXEMPT = {audit}` (the always-on class).

No other substrate was touched. The meta-harness G2 WI-1 seal was scoped to `packages/shared/` (charter is
under approved ADR-016 modification this cycle); `packages/shared/` remained untouched throughout.

---

## Section 5 — 17-agent compliance certification (Task 26)

Every agent's `nlah/README.md` carries the full ADR-007 v1.7 Hybrid Layer-1 section set (Role, Expertise,
Backend infrastructure, Charter participation, numbered Decision heuristics, numbered Stages, Failure
taxonomy, Contracts you require, What-you-never-do, **numeric Self-evolution criteria**, **Pattern
declaration**), verified by a section-presence sweep + each agent's `test_nlah_loader` suite.

| Agent                     | Grade            | Notes                                                                   |
| ------------------------- | ---------------- | ----------------------------------------------------------------------- |
| cloud-posture (F.3)       | **A**            | Reference template (#325).                                              |
| vulnerability (D.1)       | **A**            | S-4 drift fixed (registry scanning in-scope).                           |
| multi-cloud-posture (D.5) | **A**            | S-4 drift fixed (live Azure+GCP in-scope).                              |
| identity (D.2)            | **A**            | AWS-only scope current (D.2 v0.2 paused).                               |
| runtime-threat (D.3)      | **A**            |                                                                         |
| network-threat (D.4)      | **A**            |                                                                         |
| data-security (DSPM)      | **A**            | Q6 privacy contract preserved.                                          |
| k8s-posture (D.6)         | **A**            | Dedup contract preserved.                                               |
| compliance                | **A**            |                                                                         |
| threat-intel (D.8)        | **A**            |                                                                         |
| remediation (A.1)         | **A**            | Charter participation reflects the C-1 mutation gate.                   |
| investigation (D.7)       | **A**            | Charter participation reflects the C-3 worker gate + `assert_complete`. |
| audit (F.6)               | **A** (deviator) | Always-on deviation profile documented (`BY_DESIGN_EXEMPT`).            |
| supervisor (#0)           | **A** (deviator) | Router deviation profile (constructs contracts; tool items N/A).        |
| curiosity (D.12)          | **A** (deviator) | Empty-registry LLM agent; non-OCSF `CuriosityClaim`.                    |
| synthesis (D.13)          | **A** (deviator) | Empty-registry LLM-first; markdown reports.                             |
| meta-harness (A.4)        | **A** (deviator) | Self-evolution engine; the Layer-4 engine itself.                       |

**Tool-calling integrity:** `test_tool_import_guard.py` is green for all 17 — 16 routed/clean, audit
`BY_DESIGN_EXEMPT`. The audit's three bypasses (C-1/C-2/C-3) are closed and cannot recur (the guard fails
the build on any registered-tool direct call).

---

## Section 6 — Cross-agent OCSF / regression sweep (Task 27)

The M1 substrate change touches every agent's tool-dispatch path; M3 touched every NLAH. Both swept clean:

- **Full repo suite: 5299 passed, 56 skipped, 0 failed** (live AWS/Azure/GCP/K8s/NATS/Postgres lanes are
  the env-gated skips). Verified on `main` after the M1+M2 landings and re-verified per M3 PR.
- **All 17 agent suites green**, including every OCSF producer's wire-shape tests: 2002 (vulnerability),
  2003 (cloud-posture / multi-cloud / k8s-posture / data-security / compliance), 2004 (identity / runtime
  / network / threat-intel), 2005 (investigation), 2007 (remediation), 6003 (audit). No wire-shape drift.
- **Charter suite: 311 passed** — the proxy is transparent to the 9 already-gated specialists; the three
  migrated agents (remediation/vulnerability/investigation) gained +7/+4/+4 regression tests proving the
  gate binds (incl. the EXECUTE-mode mutation).
- ruff + format + mypy clean on every changed source file.

---

## Section 7 — Forward discipline locked

The standard is now inherited structurally, not by vigilance:

- **Hard tool boundary (ADR-016).** A registered tool physically cannot run off-charter; the CI guard
  blocks re-introduction. The audit's keystone question — _can an agent call a tool not in its
  `permitted_tools`?_ — is now answered **no**.
- **ADR-007 v1.7** — the objective 21-item per-agent compliance checklist (the bar every future agent and
  every M3-equivalent backfill is graded against).
- **ADR-017** — the per-cycle **NLAH-delta gate**: no v0.2+ cycle closes until its verification record
  affirms the 7 items below. This is what makes S-4 unrepeatable.

### ADR-017 NLAH-delta gate — affirmed for this cycle

1. **Scope statements current** — ✅ the two S-4 contradictions (vulnerability registry scanning,
   multi-cloud live SDK) corrected; no remaining "out of scope (vN)" line describes a shipped capability.
2. **Version labels** — ✅ stale `v0.1` framing removed from the touched NLAH prose. (The `nlah_version`
   envelope _code constant_ is intentionally untracked by M3 — a separate envelope-versioning concern.)
3. **`tools.md` accurate** — ✅ vulnerability's false "through the runtime charter" claim corrected; gated
   tools labelled; reserved tools (`osv_query`) marked.
4. **New tools registered + gated** — ✅ `is_kev`/`nvd_enrich` registered; import guard green fleet-wide.
5. **Self-evolution thresholds** — ✅ numeric thresholds added to all 17 NLAHs.
6. **Pattern declaration** — ✅ a formal block added to all 17 NLAHs.
7. **Regression sweep + NLAH consistency** — ✅ §5 (compliance) + §6 (regression) above.

---

## Section 8 — Cross-references

- Audit: [nlah-framework-audit-2026-06-09.md](nlah-framework-audit-2026-06-09.md) (#316)
- [ADR-016 — tool-proxy hard boundary](decisions/ADR-016-tool-proxy-hard-boundary.md)
- [ADR-007 v1.7 — universal compliance checklist](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- [ADR-017 — v0.2 cycle quality gate](decisions/ADR-017-v0-2-cycle-quality-gate.md)
- Spec §0 reconciliation: [agent_specification_with_harness.md](../agents/agent_specification_with_harness.md)
- M1: #317–#321 · M2: #322–#324 · M3: #325–#341 · M4: this record.

---

## What happens next

D.2 v0.2 (#314) — paused for this cycle — **resumes** with everything inherited: the hard tool boundary,
the v1.7 compliance bar as its acceptance gate, the ADR-017 delta gate, and an identity NLAH ready for the
Azure-AD scope update. Every subsequent v0.2 cycle inherits the same. **Standard set; no more drift.**

_End of verification record. The standard-setting cycle is complete._
