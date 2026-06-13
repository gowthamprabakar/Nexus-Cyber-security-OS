# v0.2 Quality Audit — 2026-06-13

**Subject:** main HEAD `cfe2886` · all 17 agents at v0.2 (meta-harness v0.2.5; curiosity pyproject
stale at 0.1.0). **Type:** depth audit (implementation reality), NOT a process audit and NOT a
cycle. **Method:** ground-truth reading with file:line evidence across 11 dimensions, calibrated
GREEN / YELLOW / RED. Full repo at audit time: 7045 passed, 72 skipped, 0 failed.

---

## Executive Summary

### Overall fleet readiness for Phase C

- **Tools (registered layer):** 50 🟢 GREEN / 0 🟡 / 0 🔴 — every charter-registered tool invokes a
  real backend on the happy path (subprocess / SDK / HTTP / workspace file read). No stub-only tools.
- **Tools (boundary integrity):** 1 🔴 RED — `apply_patch` is invoked **raw** on the remediation
  rollback path, bypassing the charter proxy (budget + audit + permission escape) on the only
  cloud-mutating agent.
- **Safety invariants:** **0 of ~36 `assert_*` invariants are wired into any agent `run()` flow** —
  the entire invariant catalog is a tested-but-unwired shelf (this is exactly the Path-1/Phase-C
  deferral, now quantified). 🟡 across the fleet.
- **Agents:** 0 🟢 GREEN / 16 🟡 YELLOW / 1 🔴 RED (remediation, due to the apply*patch bypass).
  "YELLOW" here means \_real, deep building blocks that are not yet wired into the production loop* —
  which is precisely what Phase C exists to do. It is not a quality failure; it is the baseline.

- **Phase C launch recommendation: 🟡 PROCEED WITH AMENDMENTS.** One P1 safety fix
  (apply_patch bypass) should land before Phase C wires execute loops. Everything else Phase C
  needs is real; the wiring is the work.

### Top 5 risks for Phase C

1. **`apply_patch` rollback bypass (🔴 P1, safety-critical).** `remediation/validator.py:202`
   calls `apply_patch(...)` via a raw import (`validator.py:59`), NOT through `ctx.call_tool`. The
   rollback `kubectl patch` (a real cluster mutation) executes with **no `cloud_api_calls` budget
   charge, no `tool_call` audit entry, and no permitted-tools check.** Neither guard catches it: the
   runtime proxy wraps the registry object (not the raw module symbol), and the static guard only
   scans `agent.py`/`normalizer.py` (`test_tool_import_guard.py:34`), so `validator.py` is invisible.
   This is on the one agent that mutates customer infrastructure.
2. **The safety-invariant catalog is unwired (🟡, systemic).** Zero `assert_*` invariants are called
   from any `run()` path. Remediation is the only agent whose safety _behavior_ is enforced in
   `run()` — and it does so via a **parallel `authz.enforce_*` API**, leaving its 10 named `assert_*`
   invariants dead. Phase C must wire (or, for remediation, reconcile) the whole catalog; until then
   the "26 code-level safety invariants" are not load-bearing.
3. **No `NEXUS_LIVE_*` agent lane runs in CI (🟡, systemic).** The only live flag set in any workflow
   is `NEXUS_LIVE_POSTGRES` (a substrate flag). Every agent live lane — cloud SDK, K8s sensors,
   registries, LLM, kind — is operator-run-only, proven in automation solely by skip-message
   assertions. Phase C's confidence in live behaviour currently rests on FakeLLMProvider / fixtures.
4. **Advertised "live" capability sits OUTSIDE the registered tool layer (🟡).** data-security and
   multi-cloud-posture register only JSON file-readers; their live boto3/Azure/GCS discovery lives in
   _unregistered_ `*_live.py` / `*_discovery.py` modules. network-threat registers only eve.json /
   flow-file readers — no live Suricata/Zeek/CloudWatch tool. Phase C cannot wire these as tools
   until they are registered + validated.
5. **Cross-cycle template drift + a producer-only gap (🟡).** `assert_categorical_only` and
   `assert_bounded_retry` are copy-pasted (byte-identical bodies) across D.13/D.7/D.12 — drift risk;
   should be hoisted to a shared module. Curiosity is **not** in the substrate `_FORBIDDEN_SUBSCRIPTIONS`
   fence (only remediation/supervisor/meta_harness are), so its producer-only posture rests entirely
   on an unwired per-agent guard.

### Amendment PRs required before Phase C launch

- **P1 (1):** Fix the `apply_patch` rollback bypass + widen the static guard scope. **Blocks Phase C
  launch** (safety-critical, exists now).
- **P2 (4):** Per-sub-sprint prerequisites (reconcile remediation invariants; validate live LLM;
  register/validate live multi-cloud + sensor modules; establish ≥1 live-lane CI exercise per agent
  class).
- **P3 (6):** Non-blocking hygiene (2007 comment accuracy; hoist shared invariants; curiosity fence
  entry; curiosity pyproject bump; ruff pre-commit hook; misc optional-field/doc fixes).

---

## Dimension 0 — Tool Layer (PRIMARY)

### 0.1 / 0.2 — Inventory + backend verification

**50 registered tools across 13 agents; all 🟢 GREEN (real backend on happy path).** Empty-registry
by design (N/A): curiosity, supervisor, synthesis, meta-harness.

| Agent               | tools | backend reality (evidence)                                                                                     |
| ------------------- | ----- | -------------------------------------------------------------------------------------------------------------- |
| cloud-posture       | 7     | `prowler aws` subprocess (`tools/prowler.py:48`); boto3 S3/IAM (`aws_s3.py`, `aws_iam.py`); Postgres KG writer |
| threat-intel        | 10    | file readers (NVD/KEV/ATT&CK JSON) + httpx live feeds (NVD/CISA/abuse.ch/OTX)                                  |
| k8s-posture         | 4     | kube-bench/Polaris/manifest file reads; kubernetes client (`cluster_workloads.py:153`)                         |
| multi-cloud-posture | 4     | Azure/GCP **JSON file readers** (live SDK is unregistered — see risk #4)                                       |
| network-threat      | 3     | Suricata/VPC-flow/DNS **file readers** (live sensors unregistered — risk #4)                                   |
| runtime-threat      | 3     | Falco/Tracee JSON-line reads; `osqueryi --json` subprocess                                                     |
| data-security       | 3     | S3-inventory/object/F.3 **JSON file readers** (live boto3/Azure/GCS unregistered — risk #4)                    |
| identity            | 3     | boto3 IAM (paginated), `simulate_principal_policy`, Access Analyzer — real SDK                                 |
| investigation       | 3     | AuditStore (SQLAlchemy), SemanticStore.neighbors (Postgres), sibling findings.json read                        |
| vulnerability       | 3     | `trivy` subprocess; httpx KEV + NVD (with retry)                                                               |
| audit               | 2     | audit.jsonl + episode file reads (BY_DESIGN_EXEMPT direct-read pattern)                                        |
| remediation         | 2     | findings.json read; `kubectl patch` subprocess (`kubectl_executor.py`)                                         |
| compliance          | 1     | bundled CIS YAML via importlib                                                                                 |

Honest nuance: the registered tool layer is genuinely live, but the **most-hyped multi-cloud/sensor
"live" capabilities are not in the `ctx.call_tool`-reachable surface** — they are continuous-infra
modules outside the registry (risk #4).

### 0.4 — Tool-proxy hard boundary 🔴 RED (one real bypass)

- Proxy implementation is genuine: `_ProxiedTool.__call__` raises `DirectInvocationBlocked` outside
  dispatch (`charter/tools.py:35-38`); sanctioned path `Charter.call_tool` does forbidden→budget→
  audit→dispatch (`context.py:89-112`); proven by `test_tool_proxy.py:65-71`.
- F.6 `BY_DESIGN_EXEMPT == {"audit"}` confirmed (`test_tool_import_guard.py:47`); real AST guard.
- **🔴 `apply_patch` rollback bypass (CONFIRMED):** `validator.py:202` calls the raw `apply_patch`
  imported at `validator.py:59`, reached from `agent.py:549` rollback. Escapes budget/audit/permission.
  The static guard's `_DRIVER_MODULES = ("agent.py","normalizer.py")` (`test_tool_import_guard.py:34`)
  does not scan `validator.py`; the runtime proxy can't see a raw imported symbol. **The main apply
  path is correct** (`agent.py:484-488` checks permitted_tools then `ctx.call_tool`). Boundary verdict:
  🔴 — load-bearing for the proxy object, but a registered cloud-mutating tool escapes it on a real path.

### 0.5 — Budget telemetry 🟡 YELLOW

`BudgetEnvelope.consume()` raises `BudgetExhausted`; `check_wall_clock()` measures real
`time.monotonic()`; `Charter.call_tool` reads `tools.cloud_calls(name)` and consumes it
(`context.py:99-101`) — **not decorative**. Gap: no test proves a `cloud_calls=1` tool charged
through `call_tool` actually decrements/exhausts `cloud_api_calls` (only `llm_calls` is exercised).
Combined with the apply_patch bypass, the one real cloud-mutating tool's cost is demonstrably
uncharged on the rollback path.

### 0.6 — Tool error handling 🟢 mostly GREEN

Broadly robust: typed exceptions + timeouts + graceful empty-result. Minor 🟡: cloud-posture
`aws_s3_list_buckets` / `aws_iam_list_users_without_mfa` lack try/except around the boto3 call
(`aws_s3.py:18`, `aws_iam.py:18`) — a real auth/throttle error propagates uncaught from the tool
(caught only by the charter outer scope).

### 0.7 — LLM provider layer 🟢 real / 🟡 unexercised-live

- DeepSeek via OpenAI-compatible provider: real `openai.AsyncOpenAI` client
  (`llm_openai_compat.py:68`, call `:223`). 🟢
- Anthropic fallback: real `anthropic.AsyncAnthropic` (`llm_anthropic.py:62`, call `:167`) with
  tenacity retry; `should_fallback` (5xx/429/timeout → fallback, 4xx-auth → fatal) is **tested**
  against fakes (`test_fallback_triggers.py:31-73`). 🟢
- Inheritance: synthesis/investigation/curiosity wrappers all under `providers/` (no `<agent>/llm/`);
  all import `charter.llm`, zero direct SDK imports; `test_no_per_agent_llm_module` guard present. 🟢
- **🟡 critical Phase-C intelligence:** no committed run/test path ever makes a real API call —
  everything routes through `FakeLLMProvider`. The real clients fire only if an operator sets
  `NEXUS_LIVE_*` + an API key. Live LLM behaviour is unproven in automation.

### Dimension 0 summary

Tool layer is real (50/50 GREEN) — the strongest part of v0.2. But the boundary has one
safety-critical hole (apply_patch rollback), the live capabilities for 3 agents sit outside the
registry, and the LLM layer — though real — is never exercised live in CI.

---

## Dimension 1 — Invariant load-bearing 🟡→🔴 (systemic: none wired)

**Finding: 0 of ~36 `assert_*` invariants are invoked on any agent `run()` path.** Every invariant
is defined in a standalone module (`<agent>/invariants|privacy|validation|retry|...`), exercised only
by its own unit test, and never imported by `agent.py` or a stage reachable from `agent.run`.

| Invariant family                                                                                                                                                                     | owning agents                                 | status                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| categorical_only / bounded_retry / \*\_cited                                                                                                                                         | synthesis, investigation, curiosity           | defined+tested, **not wired**                                                                               |
| worker_bounded / evidence_chain / no_speculation                                                                                                                                     | investigation                                 | defined+tested, **not wired**                                                                               |
| tenant_scoped / no_claims_subscription / llm_only_with_gaps                                                                                                                          | curiosity                                     | defined+tested, **not wired**                                                                               |
| default_recommend / action_allowlist / dry_run_first / rollback_mandatory / blast_radius / idempotent_scoped / privileged_authz / auto_mount_validation / tool_proxy / tenant_scoped | remediation                                   | defined+tested, **not wired**                                                                               |
| authorized / block_authorized                                                                                                                                                        | runtime-threat, network-threat                | called inside `actions/` subtree, but that subtree is imported nowhere outside itself+tests → **not wired** |
| privacy_contract / audit_readonly / admin_for_cross_tenant / no_peer_to_peer / signed_contract / subscription_allowed / single_cluster_context                                       | data-security, audit, supervisor, k8s-posture | **not wired**                                                                                               |

**Special case — remediation:** `run()` DOES enforce mode/allowlist/blast-radius safety, but via the
parallel `authz.enforce_mode` (`agent.py:202`), `filter_authorized_findings` (`:227`),
`enforce_blast_radius` (`:255`) API — NOT the 10 named `assert_*` invariants. The safety _behaviour_
is wired; the named _invariant functions_ are dead. Phase C must reconcile (pick one canonical path).

This is the single most important Phase-C input: the invariant library is a **shelf of unwired
guards**. Wiring it is the Phase C job; the audit confirms the building blocks exist and are tested.

---

## Dimension 2 — Test exercise depth 🟢 GREEN (sample)

8/8 sampled v0.2 modules GREEN (happy + edge + error). Highlights: audit Merkle/tamper suites cover
genesis-violation + tamper-divergence + a no-repair-surface guard; remediation `test_promotion_gate.py`
is **exemplary** — control-flow spies prove zero kubectl contact for refused findings (`:629-774`).
No skipped/missing module test files in the sample.

## Dimension 3 — Source reader integration 🟡 YELLOW (breadth not in loop)

| Agent         | declared sources        | reads live files?              | missing-source                                                  | wired into run()?                                                                        |
| ------------- | ----------------------- | ------------------------------ | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| synthesis     | 12                      | yes (read_text+json)           | skip+continue 🟢                                                | **NO** — run() still calls the v0.1 **3-agent** reader (`agent.py:157`)                  |
| investigation | 13                      | yes (via related_findings)     | skip+continue 🟢                                                | **NO** — run() reads operator-pinned `scope.sibling_workspaces`, not the 13-agent reader |
| curiosity     | 14 (registry/bucketing) | no — reads SemanticStore graph | silent-empty 🟡 (`semantic_store=None` default ingests nothing) | partial (`agent.py:151`) but empty by default                                            |

The expanded fleet readers are built + tested but **never called from any `src/` run path** — exactly
the WI-Y3/I3/X-series "breadth not depth" honesty notes, now confirmed at file:line.

## Dimension 4 — Live-gated test ratio 🟡 (systemic CI gap)

**No `NEXUS_LIVE_*` agent lane is set in any CI workflow** (only `NEXUS_LIVE_POSTGRES` in
`charter-f5-live.yml:48`). Every agent live lane is operator-run-only. Genuinely-skipping test counts
(measured by running suites with live env unset): most agents GREEN (0-2, because the _gating logic_
is tested in CI via monkeypatched probes); 🔴 multi-cloud-posture (12) + vulnerability (11) — the
multi-cloud provider lanes are the largest never-run-in-CI blocks; 🟡 cloud-posture (9), remediation
(7), investigation (3), network-threat (3).

## Dimension 5 — OCSF emission 🟢/🟡

| Emitter                                                 | class_uid/category                                                                                                                                                          | verdict           |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| cloud-posture (2003), identity (2004), curiosity (2004) | correct                                                                                                                                                                     | 🟢                |
| investigation (2005), audit (6003)                      | correct class; **no `severity_id`** (Recommended, not Required)                                                                                                             | 🟡 optional drift |
| remediation (2007)                                      | **2007 "Remediation Activity" is NOT a published OCSF v1.3 class** (category 2 Findings tops at 2006); `schemas.py:50` comment "per OCSF v1.3" overstates a fleet extension | 🟡 accuracy       |

All emitters route on `class_uid` and have class_uid unit tests. The 2007 finding is long-standing
(since A.1 v0.1), not a v0.2 regression — but the inline "per OCSF v1.3" claim is inaccurate.

## Dimension 6 — Q-lock honor 🟢/🟡

Spot-checks honor the locks in code, with the consistent caveat that "expanded source/continuous"
locks are honored as _built infrastructure_, not _run-wired behaviour_ (Dim 3/7). No Q-lock found
violated; several are 🟡 "honored but latent" (e.g. synthesis Q3 12-source reader exists but unused
in run()).

## Dimension 7 — Continuous infrastructure 🟡 YELLOW (real but unwired)

Six agents have `continuous/` (compliance, curiosity, data-security, investigation, remediation,
synthesis). All have real per-tenant `due()` cadence logic with state — **zero stubs**. compliance +
data-security go furthest with genuine `delta.py` change-detection. **None is wired into run()**
(`grep` of agent.py for continuous/scheduler/select_mode returns nothing) — the Path-1/Phase-C claim
is **accurate and verified**. The 4 non-delta schedulers are a byte-identical copy-paste template.

## Dimension 8 — Deviation guards 🟢 (one gap)

1. F.6 `BY_DESIGN_EXEMPT == {"audit"}` — 🟢 real AST guard, catches registry bypass in any
   non-exempt agent.
2. Substrate `_FORBIDDEN_SUBSCRIPTIONS` (`shared/fabric/client.py:83`) maps remediation/supervisor/
   meta_harness → `{"claims.>"}`, enforced in `subscribe()` (`:460-467`) — 🟢. **Gap:** curiosity is
   NOT in the dict; its producer-only posture rests only on the unwired `assert_no_claims_subscription`.
3. `test_no_per_agent_llm_module` — 🟢 present in all 3 LLM agents' smoke tests; real
   `importlib.util.find_spec` check.

## Dimension 9 — NLAH spot-check 🟢 GREEN (4/4)

cloud-posture / audit / investigation / remediation NLAHs all present; charter-tool counts match the
registry exactly (7 / 2 / 3 / 2); no inflated claims. Minor: audit `nlah/README.md` cites both
"ADR-007 v1.7" and stale "v1.3" — doc-only.

## Dimension 10 — Cross-cycle inheritance 🟡/🟢

- `assert_categorical_only` — 🟡 byte-identical regexes + Luhn copy-pasted across D.13/D.7/D.12, no
  shared import (drift risk).
- `assert_bounded_retry` — 🟡 same (`MAX_ATTEMPTS=2`, identical body, three copies).
- `*_cited` family — 🟢 genuinely ADAPTED (same skeleton: extract cited refs → set-diff vs
  authoritative set → raise), agent-specific reference types. Not a blind copy, not divergent.

---

## Cross-Dimension Pattern Findings

- **One root cause, many cells (the v0.2 "latent depth" pattern):** Dim 1 (invariants unwired),
  Dim 3 (expanded readers unused in run()), Dim 7 (continuous unwired) are the SAME phenomenon —
  v0.2 built deep, correct, tested building blocks and **deliberately deferred run()-wiring to
  Phase C**. This is honest and self-documented; it means the v0.2 "L2 depth" is largely latent code
  that Phase C activates. Not a defect — the baseline.
- **Boundary-vs-behaviour mismatch on remediation:** safety behaviour is wired (`enforce_*`) but the
  named invariants are dead, AND a cloud-mutating tool escapes the proxy on rollback. The one agent
  where "wired" matters most has the messiest wiring story.
- **"Live" is real in code, unexercised in automation everywhere:** tools (Dim 0.7), live lanes
  (Dim 4), live readers (Dim 3) — the real backends exist but nothing in CI drives them.

---

## Per-Agent Phase C Readiness Matrix

Legend: tools / invariants-wired / tests / continuous / **overall**. "🟡 wired=no" is the expected
baseline (Phase C does the wiring), not a failure.

| Agent                     | tools                    | invariants wired              | tests | continuous | overall |
| ------------------------- | ------------------------ | ----------------------------- | ----- | ---------- | ------- |
| cloud-posture (F.3)       | 🟢                       | ⚪ (n/a)                      | 🟢    | ⚪         | 🟢      |
| multi-cloud-posture (D.5) | 🟢\* (live unregistered) | ⚪                            | 🟢    | ⚪         | 🟡      |
| vulnerability (D.1)       | 🟢                       | ⚪                            | 🟢    | ⚪         | 🟢      |
| identity (D.2)            | 🟢                       | ⚪                            | 🟢    | ⚪         | 🟢      |
| threat-intel (D.8)        | 🟢                       | ⚪                            | 🟢    | ⚪         | 🟢      |
| runtime-threat (D.3)      | 🟢                       | 🔴 not wired                  | 🟢    | ⚪         | 🟡      |
| network-threat (D.4)      | 🟢\* (live unregistered) | 🔴 not wired                  | 🟢    | ⚪         | 🟡      |
| k8s-posture               | 🟢                       | 🔴 not wired                  | 🟢    | ⚪         | 🟡      |
| compliance                | 🟢                       | ⚪                            | 🟢    | 🟡 (delta) | 🟡      |
| data-security             | 🟢\* (live unregistered) | 🔴 not wired                  | 🟢    | 🟡 (delta) | 🟡      |
| audit (F.6)               | 🟢                       | 🔴 not wired                  | 🟢    | ⚪         | 🟡      |
| supervisor                | ⚪                       | 🔴 not wired                  | 🟢    | ⚪         | 🟡      |
| synthesis (D.13)          | ⚪                       | 🔴 not wired                  | 🟢    | 🟡         | 🟡      |
| investigation (D.7)       | 🟢                       | 🔴 not wired                  | 🟢    | 🟡         | 🟡      |
| curiosity (D.12)          | ⚪                       | 🔴 not wired                  | 🟢    | 🟡         | 🟡      |
| remediation (A.1)         | 🔴 (apply_patch bypass)  | 🔴 not wired (enforce\_\* is) | 🟢    | 🟡         | 🔴      |
| meta-harness (A.4)        | ⚪                       | ⚪                            | 🟢    | ⚪         | 🟢      |

---

## Amendment PRs Required Before Phase C Launch

### Priority 1 — BLOCKING Phase C launch

1. **Fix the `apply_patch` rollback bypass.** Route `validator.run_rollback` through `ctx.call_tool`
   (or a sanctioned in-dispatch path) so the rollback `kubectl patch` is budget-charged, audited, and
   permission-checked; AND widen `test_tool_import_guard.py:_DRIVER_MODULES` to include `validator.py`
   (+ any other module that imports registered tool symbols). Affected: `remediation/validator.py`,
   `remediation/agent.py` (rollback call site `:549`), `charter/tests/test_tool_import_guard.py`.
   Blocking-for: Phase C launch (safety-critical; the only cloud-mutating agent). Size: small-medium.

### Priority 2 — BLOCKING specific Phase C sub-sprints

2. **Remediation invariant reconciliation** — decide whether `assert_*` or `authz.enforce_*` is
   canonical; wire the chosen set into `run()` and delete/alias the other. Blocks: Phase C remediation
   sub-sprint.
3. **Validate live LLM before wiring D.13/D.7/D.12** — exercise a real DeepSeek call + a real
   Anthropic fallback once (operator env), and wire the 12/13-source readers into `run()` (they
   currently exist but `run()` uses v0.1 narrow readers). Blocks: Phase C LLM-agent sub-sprint.
4. **Register/validate live multi-cloud + sensor modules** — the live boto3/Azure/GCS discovery
   (data-security, multi-cloud-posture) + live Suricata/Zeek/CloudWatch (network-threat) are
   unregistered; register + validate them before wiring those agents' loops. Blocks: those sub-sprints.
5. **Establish ≥1 live-lane CI exercise per agent class** (or a documented operator pre-flight) so
   Phase C wiring is validated against a real backend, not fixtures. Blocks: live-mode confidence.

### Priority 3 — Recommended but not blocking

6. Correct `remediation/schemas.py:50` "per OCSF v1.3" → "fleet extension; not a published OCSF v1.3
   class" (and note in the closure-record lineage).
7. Hoist `assert_categorical_only` + `assert_bounded_retry` to a shared module (kill copy-paste drift
   across D.13/D.7/D.12).
8. Add `curiosity` to the substrate `_FORBIDDEN_SUBSCRIPTIONS` fence.
9. curiosity `pyproject.toml` version bump 0.1.0 → 0.2.0 (Cycle 15 carryover).
10. Pre-commit hook for RUF043 / S105 (the reset-trap mitigation — these aren't reliably husky-auto-fixed).
11. Misc: budget `cloud_calls` end-to-end test; investigation/audit `severity_id` (optional field);
    audit NLAH ADR-007 v1.3→v1.7 stale citation; cloud-posture list\_\* try/except.

---

## Phase C Plan Implications

- **Can launch immediately (after P1):** the non-mutating posture/detection agents (F.3, D.1, D.2,
  D.8, D.3, D.4, k8s-posture, compliance) — tools are real; wiring invariants + continuous loops is
  standard Phase C work.
- **Blocked pending P2:** remediation (P1 + invariant reconciliation), the LLM trio (live validation
  - reader wiring), and the 3 live-capability-unregistered agents (data-security, multi-cloud-posture,
    network-threat).
- **Revised Phase C timeline:** the original ~5-7 week estimate holds IF P1 lands first and P2 items
  are sequenced per sub-sprint; the unregistered-live-module work (amendment #4) is the most likely to
  expand scope and should be scoped early.

## Methodology Notes

Audited via parallel read-only investigators across the 11 dimensions, each returning file:line
evidence and GREEN/YELLOW/RED verdicts; the three highest-stakes findings (apply_patch bypass, OCSF
2007 claim, static-guard scope) were re-verified directly against main. Dim 4 skip counts were
measured by running suites with live env unset (not grep heuristics). No files were modified.

## Honest §

- **Not audited:** every line of all 50 tools (backend-invocation sites sampled deeply, not
  exhaustively); all 15 eval cases per emitter (1-2 sampled per class); every Q-lock (3×16 sampled).
- **Requires Phase C / operator to validate:** all live behaviour (no live lane runs in CI) — real
  cloud SDK calls, real K8s sensor reads, real registry scans, real DeepSeek/Anthropic calls, and the
  real kind execute+rollback path. These are GREEN-in-code but unproven-in-automation.
- **Confidence:** HIGH on the structural findings (invariant wiring, tool registration, proxy bypass,
  continuous wiring — all greppable + verified). MEDIUM on the OCSF-spec-correctness nuance (severity_id
  optionality) and on per-tool error-handling completeness (sampled).

---

**Bottom line:** v0.2 built a **real, deep, well-tested set of building blocks** — the tool layer is
genuinely live (50/50), tests are strong, OCSF emission is structurally sound, deviation guards work.
The gap Phase C must close is **wiring**: zero safety invariants, zero expanded readers, and zero
continuous loops are connected to `run()` — by design (Path 1), now quantified. One genuine
safety-critical defect (the `apply_patch` rollback proxy bypass) should be fixed before Phase C wires
execute loops. Recommendation: **PROCEED WITH AMENDMENTS** — land P1 first, sequence P2 per sub-sprint.
