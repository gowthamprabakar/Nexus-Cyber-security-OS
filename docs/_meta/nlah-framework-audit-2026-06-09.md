# NLAH Framework Quality Audit — 17 Agents × 5 Layers

**Status:** Investigation-only audit. No fixes, no NLAH updates, no code changes were made in this cycle.
**Audit date:** 2026-06-09
**Auditor:** Claude Code (orchestrated static + code analysis, with adversarial verification of all critical findings)
**Branch:** `docs/nlah-framework-quality-audit`
**Foundational spec audited against:** [docs/agents/agent_specification_with_harness.md](../agents/agent_specification_with_harness.md)

> This document establishes **ground truth**. It grades honestly against the spec, distinguishes
> "spec-literal" gaps from "de-facto-convention" gaps, and proposes remediation **options** — it does
> not prescribe. The operator decides remediation strategy after reviewing these findings. D.2 v0.2
> remains paused until that decision.

---

## Section 1 — Audit Summary

**Scope:** All 17 shipped agents, each across the five NLAH layers defined in the foundational spec, plus a dedicated tool-calling-integrity pass.

**Methodology:**

1. **Systemic anchoring** — read the charter substrate ([contract.py](../../packages/charter/src/charter/contract.py), [context.py](../../packages/charter/src/charter/context.py), [tools.py](../../packages/charter/src/charter/tools.py), [workspace.py](../../packages/charter/src/charter/workspace.py)) once, to fix the facts that are uniform across the fleet and avoid 17 inconsistent re-derivations.
2. **Objective scan** — a throwaway scanner (not committed) extracted consistent signals across all 17 agents (README section presence, tool registration, call-path, schema markers, eval counts, TODO markers).
3. **Per-agent deep audit** — 5 parallel read-only auditors, one consistent rubric, covering Layers 1–5 + tool-calling integrity, citing `file:line`.
4. **Adversarial verification** — every **critical** finding (the three tool-gating bypasses) was re-verified by direct code reading, not trusted from a single auditor.

**Grading rubric (objective):** A = fully compliant + comprehensive · B = compliant, adequate · C = partial, gaps identified · D = non-compliant / missing · F = critically broken / blocking · N/A = not applicable to this agent's role (by-design).

### Overall maturity

Two honest readings, because the spec and the implementation have diverged:

| Reading                                                                                                                                                                                                                              | Result                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Against the spec literally** (Layer-1 `ROLE/EXPERTISE/DECISION HEURISTICS/STAGES/FAILURE TAXONOMY/CONTRACTS YOU REQUIRE/WHAT YOU NEVER DO`; Layer-3 `task.yaml`+`reasoning_trace.md`+`output.yaml`; Layer-4 documented thresholds) | **0 of 17** agents fully compliant. The literal spec is followed nowhere — including the reference agent.                                                                              |
| **Against the de-facto charter convention** (the reference agent `cloud-posture` as the real standard, role-adjusted for non-specialist agents)                                                                                      | **~12 of 17** at B or better; **1** clean reference (cloud-posture); **3** carrying genuine tool-gating defects; **2** state-mutating/external-call agents with the most serious gaps. |

**The single most important finding:** the `permitted_tools` whitelist is **opt-in, not a choke point**. It is enforced only when an agent routes a call through `Charter.call_tool()`. Agents are free to `import` a tool function and call it directly, which bypasses the whitelist, the budget meter, and the charter audit event. Three agents do exactly this — including **remediation**, the only agent that mutates cloud state.

### Critical findings (detail in §5)

| #   | Severity                   | Agent               | Finding                                                                                                                                                                                                                                                                                                                                  |
| --- | -------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C-1 | **HIGH (safety-critical)** | remediation (A.1)   | Registered tool `apply_patch` is invoked **directly** in EXECUTE mode (`dry_run=False`, real `kubectl` mutation) — never through `ctx.call_tool`. Charter `permitted_tools` + budget are bypassed on the one agent that changes cloud state. (Still domain-audited via `PipelineAuditor`, so _not unaudited_ — but _not charter-gated_.) |
| C-2 | **MEDIUM (governance)**    | vulnerability (D.1) | External network tools `is_kev` (CISA KEV, httpx) and `nvd_enrich` (NVD API, httpx) are called directly in `normalizer.py` and are **not registered** at all. `tools.md` claims they route "through runtime charter" — false. Budget/whitelist bypassed.                                                                                 |
| C-3 | **LOW–MEDIUM**             | investigation (D.7) | All 5 registered worker tools (`cloud_calls=0`, read-only) invoked directly, bypassing the whitelist + charter tool-audit; also **no `assert_complete()`** at driver exit.                                                                                                                                                               |
| S-1 | **Systemic**               | all 17              | Layer-3 file schema (`task.yaml`/`reasoning_trace.md`/`output.yaml`) is implemented by **none**. Charter writes `audit.jsonl` + required outputs instead.                                                                                                                                                                                |
| S-2 | **Systemic**               | 15 of 17            | Layer-4 self-evolution criteria absent from the NLAH (only cloud-posture and remediation have a section; neither has numeric thresholds).                                                                                                                                                                                                |
| S-3 | **Systemic**               | all 17              | Layer-5 pattern declaration: patterns are implemented in code but **not declared** in most NLAH READMEs.                                                                                                                                                                                                                                 |
| S-4 | **Systemic**               | 4 of 4 v0.2 agents  | NLAH READMEs were **not updated** by their v0.2 cycles — they still say "Out of scope (v0.1)" for capabilities v0.2 shipped (see §7).                                                                                                                                                                                                    |

---

## Section 2 — Per-Agent Compliance Scorecard

`L3` is graded against the **actual charter mechanism** (`ctx.write_output` + `audit.jsonl` + `assert_complete`). Against the **spec-literal** file schema, every agent is **F** (see §8, S-1). `N/A` = by-design for that role.

| Agent                     | L1 3-Layer | L2 ExecContract | L3 Workspace | L4 Self-Evo | L5 Pattern | Tool-Calling | Overall |
| ------------------------- | ---------- | --------------- | ------------ | ----------- | ---------- | ------------ | ------- |
| cloud-posture (F.3) ★ref  | A          | A               | A            | C           | B          | A            | **A−**  |
| identity (D.2)            | B          | A               | A            | D           | B          | B            | **B**   |
| vulnerability (D.1)       | C          | B               | B            | D           | B          | **D**        | **C−**  |
| multi-cloud-posture (D.5) | B          | B               | B            | D           | A          | B            | **B**   |
| runtime-threat (D.3)      | C          | A               | A            | D           | C          | A            | **B−**  |
| network-threat (D.4)      | B          | A               | A            | D           | D          | B            | **B−**  |
| data-security (DSPM)      | B          | A               | A            | D           | C          | B            | **B**   |
| k8s-posture (D.6)         | B          | A               | A            | D           | C          | A            | **B**   |
| compliance                | B          | B               | A            | D           | A          | A            | **B**   |
| investigation (D.7)       | C          | C               | B            | D           | B          | **C**        | **C**   |
| threat-intel (D.8)        | B          | B               | A            | D           | A          | A            | **B**   |
| remediation (A.1)         | C          | D               | A            | D           | A          | **F**        | **D**   |
| curiosity (D.12)          | B          | B               | A            | C           | A          | N/A          | **B−**  |
| synthesis (D.13)          | B          | B               | A            | C           | A          | N/A          | **B−**  |
| meta-harness (A.4)        | A          | N/A             | A            | B           | A          | N/A          | **B+**  |
| audit (F.6)               | B          | A               | A            | N/A         | A          | A            | **B+**  |
| supervisor (#0)           | B          | N/A             | A            | N/A         | A          | N/A          | **B+**  |

★ref = the ADR-007 reference agent. Even it scores L4=C (self-evolution section present but no numeric thresholds) and L5=B (pattern implied in docstring, not formally declared).

**Spec-literal Layer-1 score (objective, scanner-verified):** every agent scores **0–2 of 10** literal section markers. The literal `ROLE/EXPERTISE/DECISION HEURISTICS(H1..)/STAGES(Stage1..)/FAILURE TAXONOMY(F1..)/CONTRACTS YOU REQUIRE/WHAT YOU NEVER DO` structure is used by **no agent**.

---

## Section 3 — Per-Agent Detailed Findings

> Layer-3 line repeated per agent for completeness: **confirmed none write `task.yaml`/`reasoning_trace.md`/`output.yaml`**; all use `ctx.write_output(...)` for required outputs and inherit `audit.jsonl` from the Charter. Not repeated in prose below unless an agent deviates.

### cloud-posture (F.3) — reference agent · v0.2.0

- **L1 (A):** README 102 lines; sections Mission, Inputs, Outputs, Severity policy, Reasoning style, Failure modes, Few-shot, Out-of-scope, Self-evolution boundary, Skill selection. Comprehensive; this is the de-facto standard.
- **L2 (A):** `with Charter(...)` at [agent.py:344]; `build_registry()` registers 7 tools; `ctx.assert_complete()` present.
- **Tool (A):** all 7 tools invoked via `ctx.call_tool()` ([agent.py:358,374,375]) — GATED. 7 declared = 7 registered. Pure functions called directly (correct).
- **L4 (C):** "Self-evolution boundary" section present (signing + eval-gate + canary) but **no numeric thresholds**.
- **L5 (B):** chaining + parallel-enrich implemented; pattern described in docstring, not formally declared.
- **Markers:** 0. **Risk:** none. **Remediation effort:** ~0.5 d to add thresholds + formal pattern block.

### identity (D.2) — v0.2.0

- **L1 (B):** README 65 lines; Mission, Scope, Operating principles, Output contract, Severity bands, Determinism note, Skill selection. Backend infra/charter participation not explicitly documented.
- **L2 (A):** contract used; `build_registry()` 3 tools; `with Charter(...)` [agent.py:134]; `ctx.assert_complete()` [agent.py:178].
- **Tool (B):** read tools gated via `ctx.call_tool`; `resolve_effective_grants` declared in `tools.md` but replaced by `_synthesize_admin_grants()` in v0.1 (**documented** deviation at [agent.py:14–15]); normalizers are pure (correct). Minor declared-vs-implemented mismatch.
- **L4 (D):** no self-evolution section. **L5 (B):** sequential + TaskGroup fetch; undeclared.
- **Risk:** D.2 v0.2 is the paused cycle — see §7. **Effort:** ~0.5 d.

### vulnerability (D.1) — v0.2.0 — **CRITICAL C-2**

- **L1 (C):** README 63 lines; Mission, Scope, Operating principles, Output contract, Severity bands, Determinism note. No charter-participation doc.
- **L2 (B):** `with Charter(...)` [agent.py:99]; `build_registry()` registers **only** `trivy_image_scan` [agent.py:41]; `ctx.assert_complete()` present.
- **Tool (D) — verified bypass:** `is_kev` ([tools/kev.py:94], httpx → CISA KEV) and `nvd_enrich` ([tools/nvd.py:149], httpx → NVD API) are invoked directly in [normalizer.py:130–132] via `tg.create_task(...)`. Neither is registered. `tools.md` line 3 claims "Permissions and budget impact go through runtime charter" — **contradicted by code**. `osv_query` declared in `tools.md` but never registered or invoked.
- **L4 (D):** none. **L5 (B):** scan→normalize→report; TaskGroup for concurrent scans.
- **Risk:** two **external network** integrations escape budget + whitelist; `tools.md` is actively misleading. **Effort:** ~1 d (register + route through `ctx.call_tool`, or formally reclassify + correct `tools.md`).

### multi-cloud-posture (D.5) — v0.2.0

- **L1 (B):** README 73 lines; Mission, Source flavors, Scope, Operating principles, Failure taxonomy (F1–F4), What you never do, Skill selection. Adequate.
- **L2 (B):** `with Charter(...)` [agent.py:138]; `build_registry()` 4 readers; `ctx.assert_complete()` [agent.py:192]. `workspace_mgr` not used directly.
- **Tool (B):** 4 readers gated via `ctx.call_tool`; normalizers/summarizer are pure functions called directly (correct) — but `tools.md` lists them alongside gated tools, creating a **taxonomy ambiguity** (reads as a 7-vs-4 mismatch).
- **L4 (D):** none. **L5 (A):** 5-stage pipeline declared in README + matches code.
- **Risk:** low (ambiguity, not defect). NLAH drift — see §7. **Effort:** ~0.5 d.

### runtime-threat (D.3) — v0.1.0

- **L1 (C):** README 66 lines; Mission, Scope, Operating principles, Output contract, Severity bands, Determinism note. **No failure taxonomy, no self-evolution.**
- **L2 (A):** `with Charter(...)` [agent.py:120]; 3 tools registered; `ctx.call_tool` [agent.py:186,191,196]; `ctx.assert_complete()` [agent.py:165].
- **Tool (A):** 3 declared = 3 registered, all gated; pure normalizers direct (correct).
- **L4 (D):** absent. **L5 (C):** TaskGroup-parallel ingest + chaining present, undeclared.
- **Risk:** low. **Effort:** ~0.5 d (add failure taxonomy + self-evo + pattern block).

### network-threat (D.4) — v0.1.0

- **L1 (B):** README 69 lines; Mission, Detector flavors, Scope, Operating principles, Failure taxonomy, What you never do, Skill selection.
- **L2 (A):** `with Charter(...)` [agent.py:142]; 3 ingest tools; `ctx.call_tool` [agent.py:208,213,218]; `ctx.assert_complete()` [agent.py:190].
- **Tool (B):** 3 registered/gated; detectors + `enrich_with_intel` are pure, called directly (correct); `tools.md` lists 8 surfaces (5 pure) → naming/reality gap.
- **L4 (D):** absent. **L5 (D):** parallel + chaining in code, undeclared.
- **Risk:** low. **Effort:** ~0.5 d.

### data-security (DSPM) — v0.1.0

- **L1 (B):** README 90 lines; strong **Q6 privacy contract** (runtime-enforced via `SummarizerQ6Violation`), Failure taxonomy (F1–F4), What you never do.
- **L2 (A):** `with Charter(...)` [agent.py:145]; 3 tools registered; ingest + `read_f3_findings` via `ctx.call_tool` [agent.py:221,226,336]; `ctx.assert_complete()` [agent.py:204].
- **Tool (B):** 3 gated tools correct; 6 pure functions in `tools.md` create false mismatch.
- **L4 (D):** absent. **L5 (C):** stages described, patterns undeclared.
- **Risk:** low. **Effort:** ~0.5 d.

### k8s-posture (D.6) — v0.1.0

- **L1 (B):** README 78 lines; Mission, Source flavors, Scope, **Charter contract**, **Dedup contract**, Output contract, Skill selection. No failure taxonomy / self-evolution.
- **L2 (A):** `with Charter(...)` [agent.py:140]; 4 tools registered; `ctx.call_tool` [agent.py:229,234,255]; `ctx.assert_complete()` [agent.py:197].
- **Tool (A):** all gated tools registered; pure normalizers/dedupe direct (correct). Clean.
- **L4 (D):** absent. **L5 (C):** parallel + chaining, undeclared.
- **Risk:** low. **Effort:** ~0.5 d.

### compliance — v0.1.0

- **L1 (B):** README 73 lines; Mission, Correlator flavors, Scope, Operating principles, Failure taxonomy, What you never do, Skill selection.
- **L2 (B):** `with Charter(...)` [agent.py:138]; `build_registry()` 1 tool (`read_cis_aws_benchmark`); `ctx.assert_complete()` [agent.py:202].
- **Tool (A):** 1 declared = 1 registered, gated [agent.py:143]; correlators/scorer/summarizer pure, direct (correct).
- **L4 (D):** failure taxonomy present; no self-evolution. **L5 (A):** 7-stage pipeline declared + matches (TaskGroup at correlate).
- **Risk:** low; single-tenant SemanticStore opt-in blocked on F.5 SET LOCAL tenant-RLS substrate (known, parked). **Effort:** ~0.5 d.

### investigation (D.7) — v0.1.0 — **CRITICAL C-3**

- **L1 (C):** README 85 lines; Mission, Sub-agent flavors, Scope, Operating principles, Output contract, Skill selection. **No failure taxonomy section.**
- **L2 (C):** `with Charter(...)` [agent.py:152]; `build_registry()` 5 tools [agent.py:106–110]; **`ctx.assert_complete()` missing** at driver exit.
- **Tool (C) — verified bypass:** all 5 registered worker tools invoked **directly** inside `_worker` closures — `audit_trail_query` [agent.py:298], `find_related_findings` [agent.py:307,325], `memory_neighbors_walk` [agent.py:317] — not via `ctx.call_tool`. They are `cloud_calls=0` read-only reads of the audit store / semantic store / filesystem, so **no external or mutation impact**, but the whitelist + charter tool-audit are bypassed and the orchestrator-workers sub-agent path is not charter-scoped.
- **L4 (D):** principles present, no failure taxonomy/thresholds. **L5 (B):** orchestrator-workers declared + implemented (depth/parallel caps enforced in `orchestrator.py`).
- **Risk:** medium — the orchestrator-workers pattern is the template for future sub-agent hoists; bypass here sets a bad precedent. **Effort:** ~1 d (route worker calls through a child-scoped charter + add `assert_complete`).

### threat-intel (D.8) — v0.1.0

- **L1 (B):** README 73 lines; mirrors compliance structure; Failure taxonomy + What you never do present.
- **L2 (B):** `with Charter(...)` [agent.py:166]; 3 feed-readers registered; `ctx.assert_complete()` [agent.py:231].
- **Tool (A):** 3 declared = 3 registered, gated; correlators pure/direct (correct).
- **L4 (D):** failure taxonomy yes, self-evolution no. **L5 (A):** 6-stage pipeline declared + matches (TaskGroup at ingest + correlate).
- **Risk:** low. **Effort:** ~0.5 d.

### remediation (A.1) — v0.1.0 — **CRITICAL C-1 (safety-critical)**

- **L1 (C):** README 113 lines; Mission, Operational tiers, 7-stage pipeline, action classes, Safety primitives, Output contract, Charter contract, mode guidance. No formal failure taxonomy.
- **L2 (D):** `with Charter(...)` [agent.py:208]; `build_registry()` registers `read_findings` + `apply_patch` [agent.py:110–111] — **but the registry is never used to dispatch**.
- **Tool (F) — verified bypass:** `read_findings` called directly [agent.py:223]; `apply_patch` called directly in **both** dry-run [agent.py:439] and **EXECUTE mode `dry_run=False`** [agent.py:477]. The state-mutating `kubectl` path (`cloud_calls=1`) never passes through `ToolRegistry.call()`, so `permitted_tools` and charter budget do not gate it. Authorization is checked upstream at Stage-2 (`filter_authorized_findings`) and the action is logged via the domain `PipelineAuditor` — so the mutation is **authorized and domain-audited**, but **not charter-gated**. For the only agent that changes customer infrastructure, the charter is not in the loop at the mutation boundary.
- **L4 (D):** blast-radius cap + rollback window present in code, not framed as self-evolution thresholds.
- **L5 (A):** 7-stage promotion-gate pipeline declared + matches.
- **Risk:** **HIGH** — this is the governance keystone agent. **Effort:** ~1–1.5 d (route `apply_patch` through `ctx.call_tool` so `permitted_tools` + budget + charter audit gate the mutation; add a pre-execute permitted_tools re-check).

### curiosity (D.12) — v0.1.0

- **L1 (B):** README 64 lines; What you do, Pipeline (7 stages), **Q6 invariant**, hypothesis style, What you do NOT do, Skill selection.
- **L2 (B):** `with Charter(...)` [agent.py:144]; `build_registry()` returns an **empty** registry by design; LLM routed via `charter.llm_provider`.
- **Tool (N/A):** zero charter-registered tools (documented in `tools.md`); in-driver helpers + substrate reads are not cloud-budgeted. Acceptable by design — but note this means curiosity has **no** charter tool-gate at all.
- **L4 (C):** Q6 retry budget (1) present; no eval-gate/thresholds. **L5 (A):** 7-stage pipeline declared + matches.
- **Markers:** the only fleet agent with TODO/FIXME density (retry/fallback paths) per scan. **Risk:** low. **Effort:** ~0.5 d.

### synthesis (D.13) — v0.1.0

- **L1 (B):** README 60 lines; What you do, Pipeline (6 stages), Q6 invariant, style, What you do NOT do, Skill selection.
- **L2 (B):** `with Charter(...)` [agent.py:150]; empty registry by design; first LLM-call agent; LLM via `charter.llm_provider`.
- **Tool (N/A):** zero registered tools (by design, documented).
- **L3 note:** `_envelope()` is built then discarded (`del envelope`) — future-proofing for v0.2 OCSF; reads as dead code without a comment.
- **L4 (C):** Q6 retry budget; no thresholds. **L5 (A):** 6-stage pipeline declared + matches.
- **Risk:** low. **Effort:** ~0.5 d.

### meta-harness (A.4) — v0.2.5 — self-evolution engine

- **L1 (A):** README 99 lines; dual-posture persona (v0.1 read-only → v0.2 auto-acting), v0.2 amendments, 8-stage pipeline, report style, deferrals, conformance pointers. Comprehensive.
- **L2 (N/A by design):** does not receive or construct an `ExecutionContract`; no `with Charter(...)`. It imports tool functions directly ([agent.py:85–91]) and operates on eval-suite **scorecards** + other agents' outputs.
- **Tool (N/A by design):** orchestrator of internal functions, not charter-gated tools. Acceptable for role.
- **L4 (B):** **this is the engine** — README documents trigger criteria (≥5 tool calls, no failure/escalation, hash novelty) + mandatory eval-gate. The fleet-wide L4 gap (S-2) is that the _other_ agents don't expose the thresholds this engine needs.
- **L5 (A):** evaluator-optimizer/orchestrator declared + matches.
- **Markers:** 1 intentional `NotImplementedError` (`skill_lifecycle.py` — Task-15 operator-approval CLI seam; load-bearing deferral).
- **Risk:** see §6 (operability). **Effort:** n/a for self.

### audit (F.6) — v0.1.0 — always-on class

- **L1 (B):** README 59 lines; Mission, Scope, Operating principles (6), Output contract, NL query phrasing, Skill selection. Compact, adequate.
- **L2 (A):** `with Charter(...)` [agent.py:89]; `build_registry()` 2 tools; always-on budget policy (hard wall-clock, warn+proceed on others) [agent.py:156].
- **Tool (A, by-design direct):** `audit_jsonl_read` + `episode_audit_read` called directly [agent.py:188–189] — the always-on class intentionally skips the budget gate (ADR-007 v1.3). Read-only.
- **L4 (N/A):** read-only auditor; no self-evolution by role. **L5 (A):** chain-writer declared + matches.
- **Risk:** none. **Deviation verdict: by-design.** Recommend a one-line ADR note (see §9).

### supervisor (#0) — v0.1.0 — router/dispatcher

- **L1 (B):** README 75 lines; persona, what-you-do, 5-stage pipeline, forbidden-subscription invariant (Q-ARCH-1), routing style, deferrals, conformance pointers.
- **L2 (N/A by design):** **constructs** delegation contracts for downstream agents rather than receiving one; no `with Charter(...)`, no `ToolRegistry`.
- **Tool (N/A by design):** routing is declarative rule-matching; no charter-gated tools.
- **L4 (N/A):** stateless rule-based router; evolution deferred to v0.2. **L5 (A):** routing declared + matches.
- **Risk:** none. **Deviation verdict: by-design.** Recommend a one-line ADR note (see §9).

---

## Section 4 — Cross-Agent Pattern Analysis

**Canonical pattern usage (from code, across the fleet):**

| Pattern                               | Agents implementing (in code)                                                                                  | Declared in NLAH?                            |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Prompt chaining (sequential stages)   | ~all 13 specialists                                                                                            | Rarely named; described as "pipeline/stages" |
| Parallelization (`asyncio.TaskGroup`) | cloud-posture, runtime, network, data-sec, k8s, compliance, threat-intel, multi-cloud, identity, vulnerability | Almost never named                           |
| Routing                               | supervisor (primary), runtime/network (secondary)                                                              | supervisor: yes                              |
| Orchestrator-workers                  | investigation (primary), meta-harness                                                                          | investigation: yes; meta: yes                |
| Evaluator-optimizer (self-evolution)  | meta-harness (engine)                                                                                          | meta: yes                                    |

**Patterns used but NOT declared (S-3):** parallelization and chaining are pervasive in code but absent from most READMEs' pattern sections. Net effect: the runtime cannot read a declared-pattern contract from the NLAH for 13 of 17 agents — it would have to infer from code.

**Patterns declared but NOT implemented:** none found. No agent over-claims a pattern.

**Best-declared:** multi-cloud-posture, compliance, threat-intel, meta-harness, supervisor (declared pipeline/pattern matches code).

---

## Section 5 — Tool-Calling Integrity Analysis

**The gate, precisely:** `ToolRegistry.call(name, permitted=...)` raises `ToolNotPermitted` when `name ∉ contract.permitted_tools` ([tools.py:32–37]). It is reached **only** via `Charter.call_tool()` ([context.py:88–105]), which also consumes budget and writes a `tool_call` audit event. **There is no interception** — nothing forces an agent's tool invocations through this path.

**Consequence — answer to the operator's governance question:** _Can an agent currently call a tool not in its `permitted_tools`?_ **Yes.** Any agent can `import` a tool function and call it directly, fully bypassing the whitelist, budget, and charter audit. The whitelist is **advisory at the call site**, not a hard boundary.

### Per-agent call-path inventory

| Agent             | Declared (`tools.md`) | Registered | Invoked via `ctx.call_tool` (gated) | Invoked directly                                     | Verdict                 |
| ----------------- | --------------------- | ---------- | ----------------------------------- | ---------------------------------------------------- | ----------------------- |
| cloud-posture     | 7                     | 7          | 7                                   | pure fns only                                        | ✅ gated                |
| identity          | 5                     | 3          | 3                                   | pure + documented sub                                | ✅ (minor doc delta)    |
| multi-cloud       | 7 (mixed)             | 4          | 4                                   | pure fns                                             | ✅ (taxonomy ambiguity) |
| runtime-threat    | 3 (+pure)             | 3          | 3                                   | pure fns                                             | ✅ gated                |
| network-threat    | 8 (5 pure)            | 3          | 3                                   | pure fns                                             | ✅ gated                |
| data-security     | 9 (6 pure)            | 3          | 3                                   | pure fns                                             | ✅ gated                |
| k8s-posture       | 7 (mixed)             | 4          | 4                                   | pure fns                                             | ✅ gated                |
| compliance        | 1 (+pure)             | 1          | 1                                   | pure fns                                             | ✅ gated                |
| threat-intel      | 3 (+pure)             | 3          | 3                                   | pure fns                                             | ✅ gated                |
| **vulnerability** | 4                     | **1**      | 1 (trivy)                           | **`is_kev`, `nvd_enrich` (external, unregistered)**  | ❌ **C-2 bypass**       |
| **investigation** | 5                     | 5          | **0**                               | **5 registered tools direct**                        | ❌ **C-3 bypass**       |
| **remediation**   | 2                     | 2          | **0**                               | **`read_findings`, `apply_patch` (mutation) direct** | ❌ **C-1 bypass**       |
| curiosity         | 0                     | 0          | 0                                   | helpers (by design)                                  | ⚪ N/A                  |
| synthesis         | 0                     | 0          | 0                                   | helpers (by design)                                  | ⚪ N/A                  |
| meta-harness      | n/a                   | 0          | 0                                   | internal fns (by design)                             | ⚪ N/A                  |
| audit             | 2                     | 2          | 0                                   | direct (always-on, by design)                        | ⚪ by-design            |
| supervisor        | 0                     | 0          | 0                                   | router (by design)                                   | ⚪ N/A                  |

**`forbidden_tools` enforcement:** the `ExecutionContract` schema has **no `forbidden_tools` field** ([contract.py]) — the spec's `forbidden_tools` concept (e.g. cloud-posture spec line 299) is **not implemented anywhere**. Forbidden-tool prevention relies entirely on the (opt-in) `permitted_tools` allowlist.

**Audit logging of tool calls:** only tools dispatched via `ctx.call_tool` emit a `tool_call` event into `audit.jsonl`. The three bypassing agents' tool calls do not appear in the charter audit (remediation's appear in the separate `PipelineAuditor` chain; vulnerability's and investigation's external/internal reads are not in the charter chain at all).

---

## Section 6 — Meta-Harness Operability Check

**How Meta-Harness actually operates (verified):** it runs each agent's **eval suite** via `BatchEvalRunner.run_batch(...)`, produces `agent_scorecard` entities, computes deltas vs prior scorecards, flags regressions, and (v0.2) gates skill candidates. It does **not** read `reasoning_trace.md` — despite the spec's Layer-4 design ([agent_specification...md:346] "Meta-Harness reads `reasoning_trace.md`"). The raw-trace pathway is explicitly deferred: [compilation_factory.py:27–32] states trainsets need "originating traces persisted with deployed skills, which does not exist yet… a post-v0.2.5 follow-up (v0.3 candidate)."

| Operability input                                        | Status across 17                                                                                 |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Eval suite present                                       | **17 of 17** (10 cases each; meta 25, remediation 15, supervisor 15)                             |
| Scorecard-driven operability **today**                   | **17 of 17** — Meta-Harness can score and regression-flag every agent now                        |
| Raw `reasoning_trace.md` available                       | **0 of 17** — blocks the trace-based DSPy/GEPA compilation path fleet-wide (documented v0.3 gap) |
| Self-evolution **trigger thresholds** documented in NLAH | **2 of 17** (cloud-posture, remediation — and neither numeric)                                   |

**Verdict:** Meta-Harness is **operable on all 17 today** through the scorecard/eval mechanism — the directive's premise that "6 agents can't self-evolve" is, on the implemented mechanism, **better than feared for triggering coverage but worse for documented criteria**: 15 of 17 lack the documented failure thresholds the spec envisions, and 0 of 17 support the trace-based optimization pathway. What's blocking deeper self-evolution is not missing eval suites — it's (a) undocumented per-agent thresholds and (b) un-persisted raw traces.

---

## Section 7 — v0.2 Cycle Impact Assessment (NLAH drift)

**Question:** did the F.3 / D.5 / D.1 v0.2 cycles update the NLAH? **Finding: the code shipped, the NLAH did not.** All four v0.2.0 agents carry NLAH text that still describes **v0.1** scope, and three explicitly list now-shipped capabilities as out-of-scope:

| Agent (pkg ver)             | NLAH still says…                                                                    | Reality post-v0.2                                                     | Drift                                                         |
| --------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------- |
| cloud-posture (0.2.0)       | "## Out-of-scope (**NLAH version 0.1**)" header                                     | shipped at v0.2                                                       | Version label stale                                           |
| multi-cloud-posture (0.2.0) | "v0.1 is **offline-only**"; "**Out of scope (v0.1):** live SDK calls (Phase 1c)"    | D.5 v0.2 shipped **live Azure + GCP** (record #288)                   | **NLAH contradicts shipped scope**                            |
| vulnerability (0.2.0)       | "**Out of scope (v0.1):** … private-registry auth across providers… Phase 2+"       | D.1 v0.2 shipped **live ECR/ACR/GCR registry scanning** (record #312) | **NLAH contradicts shipped scope**                            |
| identity (0.2.0)            | "**Out of scope (v0.1):** … Azure AD / Entra, GCP IAM"; "Determinism note for v0.1" | D.2 v0.2 **paused** (only Task-1 bootstrap merged, #314)              | Version label stale; scope statement still accurate _for now_ |

**Specific answer to the operator's question** — _"does any agent's NLAH say 'Out of scope (v0.1): X' while X is now actually IN scope post-v0.2?"_ — **Yes: multi-cloud-posture** (live SDK calls) **and vulnerability** (private-registry scanning). These are the clearest evidence of the compounding-gap risk the directive warned about: each v0.2 cycle updated implementation and eval suites but left the natural-language harness describing the prior version.

> Note: the exact shipped-scope statements above are corroborated by the closed-cycle records (#288, #312) referenced in project memory; the operator may wish to confirm against those PRs during review. The NLAH text and version pins were read directly and are exact.

---

## Section 8 — Foundational Spec Drift

Comparing implementation to [agent_specification_with_harness.md](../agents/agent_specification_with_harness.md):

**Met across the fleet:**

- Layer-2 `ExecutionContract` exists, is rich (required_outputs, budget, permitted_tools, completion_condition, escalation_rules, workspace, persistent_root) and is validated ([contract.py]). 15/17 agents consume it (supervisor constructs, meta-harness operates above it — both by design).
- Charter context-manager lifecycle (ADR-002) is real and used by all 13 specialists.
- Eval suites exist for all 17 (ADR-007 reference shape).

**Partial coverage:**

- **Layer-1 (S, structural):** the spec's literal NLAH (`ROLE/EXPERTISE/DECISION HEURISTICS/STAGES/FAILURE TAXONOMY/CONTRACTS YOU REQUIRE/WHAT YOU NEVER DO`, single `nlah.md`) is implemented by **no agent**. The implemented convention is a `nlah/` directory (`README.md` + `tools.md` + `examples/`) with semantic-equivalent sections. **The spec doc and the reference agent disagree** — the spec was never reconciled to the as-built convention.
- **Budget field names:** spec uses `max_llm_calls`/`max_tokens`/`max_wall_clock_seconds`/`max_cloud_api_calls`; implementation uses `budget.{llm_calls,tokens,wall_clock_sec,cloud_api_calls,mb_written}`. Functionally equivalent, names drifted.

**Systemic gaps:**

- **S-1 — Layer-3 file schema not implemented (0/17):** spec prescribes `task.yaml` + `scan_outputs/` + `findings/` + `reasoning_trace.md` + `output.yaml`. Implementation writes `audit.jsonl` (charter) + flat required outputs via `ctx.write_output`. The prescribed raw `reasoning_trace.md` — the substrate the spec's Layer-4 self-evolution depends on — exists nowhere.
- **S-2 — Layer-4 self-evolution criteria not documented (15/17):** spec prescribes per-agent thresholds (e.g. "FP rate > 15% over rolling 500"). Only cloud-posture + remediation have any section; none have numeric thresholds.
- **`forbidden_tools` absent:** spec prescribes per-agent `forbidden_tools`; the contract schema has no such field.

**ADR-007 amendment reflection (v1.1–v1.6):** v1.1 (LLM adapter hoist) and v1.2 (NLAH-loader hoist) are honored fleet-wide (shared shims). v1.3 (always-on class) is implemented by audit. v1.4–v1.6 (progressive-disclosure skills, effectiveness scoring, DSPy programs) are v0.2+ surfaces not yet exercised by v0.1 agents — consistent with their version, not a gap.

---

## Section 9 — Remediation Roadmap (recommendations only)

> Effort estimates are engineering-days at the observed code size; they are honest order-of-magnitude, not commitments.

### Critical (safety / governance) — ~3–4 d

- **C-1 remediation tool-gate (HIGH):** route `apply_patch` (esp. EXECUTE mode) through `ctx.call_tool` so `permitted_tools` + budget + charter audit gate the mutation; add a pre-execute permitted_tools re-check. ~1–1.5 d.
- **C-2 vulnerability external tools:** register `is_kev`/`nvd_enrich` (or formally reclassify) and route through the charter; correct the false "through runtime charter" claim in `tools.md`. ~1 d.
- **C-3 investigation worker tools + `assert_complete`:** route the 5 worker tools through a child-scoped charter; add `ctx.assert_complete()`. ~1 d.
- **Cross-cutting (design decision, not just code):** decide whether `permitted_tools` should be a **hard** boundary (e.g. charter-injected tool proxies so direct imports can't bypass) or remain an opt-in convention. This is the keystone governance question. ~0.5 d to spec; larger to implement.

### High (blocks clean v0.2 cycles) — ~2–3 d

- **S-4 NLAH drift:** update multi-cloud-posture + vulnerability (and version labels on all four v0.2 agents) so the NLAH matches shipped scope **before** D.2 v0.2 adds more. Establish a checklist gate: "v0.2 cycle updates NLAH + version label." ~1 d + process.
- **Decide the Layer-1 source of truth:** reconcile the foundational spec to the as-built `nlah/` convention (or vice-versa) so future agents have an unambiguous template. ~1 d.

### Medium (quality / self-evolution enablement) — ~4–6 d

- **S-2 Layer-4 thresholds:** add per-agent self-evolution criteria (numeric thresholds) to all 17 NLAHs so Meta-Harness has documented triggers. ~0.25 d × 17.
- **S-3 pattern declarations:** add a formal pattern block to the 13 specialists' READMEs. ~0.1 d × 13.
- **Layer-1 backfill:** bring the thin READMEs (vulnerability, runtime-threat, investigation) up to the cloud-posture reference bar. ~0.5 d each.

### Low (cleanup) — ~1–2 d

- `tools.md` taxonomy: split "charter-gated tools" from "pure helpers" (multi-cloud, network, data-sec, k8s) to remove false mismatches.
- synthesis `del envelope` comment; curiosity TODO/FIXME triage.
- S-1 raw-trace persistence is **explicitly deferred to v0.3** (compilation_factory) — recommend leaving as-is unless trace-based optimization is pulled forward.

**Total estimated remediation effort:** ~**10–15 engineering-days** for Critical+High+Medium; the Critical band alone is ~3–4 d.

### Recommendation options for the operator

- **Option A — Full backfill before any v0.2.** Close every gap (Critical→Medium) fleet-wide, then resume D.2 v0.2. Safest; ~2–3 weeks; maximal delay.
- **Option B — Critical-only, then resume with discipline (recommended).** Fix C-1/C-2/C-3 + the `permitted_tools` boundary decision + S-4 drift for the two contradicting agents (~5–6 d), add a v0.2 "NLAH+version" gate, then resume D.2 v0.2. Carry S-2/S-3/Layer-1 backfill as tracked debt with a deadline.
- **Option C — Phased catch-up alongside v0.2.** Fix only C-1 (the safety-critical mutation gate) now; fold the rest into each agent's next v0.2 cycle. Fastest to resume; leaves C-2/C-3 governance gaps open longer.
- **Option D — Boundary-first.** Treat the opt-in `permitted_tools` finding as the root cause: implement charter-injected tool proxies so direct-import bypass becomes structurally impossible, which closes C-1/C-2/C-3 as a class rather than one-by-one. Higher up-front cost, eliminates the whole bypass category.

This audit does not choose. The data supports **B** or **D** depending on whether the operator wants speed-to-resume (B) or a structural fix to the bypass class (D).

---

## Section 10 — Cross-References

- Foundational spec: [docs/agents/agent_specification_with_harness.md](../agents/agent_specification_with_harness.md)
- ADR-002 — Charter as context manager: [docs/\_meta/decisions/ADR-002-charter-as-context-manager.md](decisions/ADR-002-charter-as-context-manager.md)
- ADR-007 — Cloud Posture reference agent (+ v1.1–v1.6 amendments): [docs/\_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-010 — Version extension template
- Platform readiness inventory: [docs/\_meta/nexus-platform-readiness-2026-06-07.md](nexus-platform-readiness-2026-06-07.md)
- Charter substrate read in this audit: [contract.py](../../packages/charter/src/charter/contract.py) · [context.py](../../packages/charter/src/charter/context.py) · [tools.py](../../packages/charter/src/charter/tools.py) · [workspace.py](../../packages/charter/src/charter/workspace.py)
- F.3 v0.2 verification record — #267
- D.5 v0.2 verification record — #288
- D.1 v0.2 verification record — #312
- D.2 v0.2 plan — #314 (**paused pending this audit + operator remediation decision**)

---

_End of audit. Investigation only — no fixes applied. Operator review → remediation decision → D.2 v0.2 resumes or remediation cycle launches first._
