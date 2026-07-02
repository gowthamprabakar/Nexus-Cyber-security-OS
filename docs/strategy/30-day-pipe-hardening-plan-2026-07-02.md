# 30-Day Pipe-Hardening Plan (v3 — twice devil-critiqued, code-verified)

**Created 2026-07-02.** v1 → v2 fixed the dormancy/measure/KMS gaps. **v3** fixes the gaps found on a
SECOND verified critique: (A) NEX-001 "land the queue" is **operator-gated — I cannot merge** (env
classifier blocks `gh pr merge`), so execution runs on the **integration branch**, operator lands to
main; (B) `run()` fixture support is **not uniform** — identity/appsec have only `semantic_store`, no
feed param, so wiring is per-agent, not one seam; (C) the KMS-as-sink migration has a **convergence
cascade** — identity's `HAS_ACCESS_TO`→KMS (written as `CLOUD_RESOURCE`) breaks if KMS changes
category; (D) coverage needs a **fixed denominator** (a target family catalog) or the % is arbitrary;
(E) hardening the 10 built families must come **before** building on them. Discipline unchanged:
**every impl ticket ships detector/change + red-team bank + e2e-proving-path-emergence + run()-wiring.**

### v3 verified corrections (the second-pass devil critique)
1. 🔴 **NEX-001 is not mine** — `gh pr merge` is env-blocked. Reframed: build on `feat/near-term-roadmap`
   (has all 10 families + report card); operator merges to main. No ticket assumes I can land to main.
2. 🔴 **NEX-004 wiring is per-agent** — data-security/network/k8s/cloud-posture/vulnerability accept
   feeds; **identity + appsec need a fixture-feed param added to `run()` first.** Wiring is a theme, not
   one ticket.
3. 🔴 **NEX-202 KMS spike must resolve the convergence cascade** — only cloud-posture writes KMS (as
   `CLOUD_RESOURCE{kind:kms-key}`); changing its category orphans any `HAS_ACCESS_TO`→KMS edge. The spike
   evaluates a property-predicated sink (no category change) vs a category migration + `record_access`
   awareness. Leaning property-predicated to avoid the cascade.
4. 🟡 **NEX-003 needs a denominator** — define a fixed **target attack-path family catalog** (MITRE
   ATT&CK-for-Cloud-derived) FIRST; coverage = families-produced / families-in-catalog. Without it, % is
   arbitrary.
5. 🟡 **Harden-built-families (NEX-408) moves to Sprint 1** — a bug in a shipped family cascades into
   everything built on it in S2–S3.
6. 🟡 **Multi-cloud parity scoped explicitly** — parity target = {leaked-cred ✅3, CAN_REACH, stored-secret,
   escalation, K8s-escape}; each named, not a vague "parity."
7. 🟡 **Spikes are timeboxed (1 day each); capacity: ~26 tickets/30 days is tight** — MUST-core marked ★,
   the rest is stretch that slips before the core does.

## Non-negotiable principles baked into v2

- **Instrument before you claim.** Coverage is measured (Sprint 0), re-measured every sprint. No
  fabricated %.
- **Wire as you build.** Every new/changed edge family ships wired into a **fixture-driven `run()`**
  (not just a unit test) — dormancy is the #1 gap; we do not grow it.
- **Spike before you size.** Genuinely uncertain work (KMS/DB sinks, CI/CD reverse-edge, depth
  strategy) gets a timeboxed SPIKE that outputs a design + a firm estimate BEFORE the impl ticket.
- **Never break a green path.** A locked regression suite (the 10 built families + report-card
  runner) must stay green after every foundation/substrate ticket.

## DoD (every impl ticket): detector/change · red-team bank · path-emergence e2e · run()-wiring (fixture) · mypy+suite green · regression suite still green · guard test if it's a seam.

---

## SPRINT 0 — LAND + MEASURE + LOCK (Days 1–3) ★ new, was missing

*You cannot improve what isn't landed or measured. This unblocks everything.*

### NEX-000 — Working-branch reality (operator-gated merge) — S ★ honest start
I **cannot merge** (`gh pr merge` env-blocked). Execution runs on `feat/near-term-roadmap` (contains all
10 families + report card + Sprint work). **Operator** merges #784–#792 (and later PRs) to `main`; I
`grep`-verify what actually landed. **AC:** a documented working branch + the operator merge checklist.

### NEX-002 — Regression lock: the green-path suite — S ★ safety keystone
Tag the current passing set (10 built families + report-card runner + convergence e2es) as
`test_regression_locked`. **AC:** one command runs it; required gate for every later ticket.
**Test:** the suite runs green on the working branch; wired as a blocking check.

### NEX-003a — Target family catalog (the coverage DENOMINATOR) — S ★ was missing
Define a fixed list of target attack-path families derived from **MITRE ATT&CK for Cloud** (the finite
compass) — the denominator. Without it, "coverage %" is arbitrary. **AC:** a committed catalog file
(N target families with source→sink shape). **Test:** the catalog loads; each built family maps to one.

### NEX-003 — Coverage instrumentation harness — M ★ metric keystone
**Depends:** 003a. Counts which catalog families the fixture bank actually produces → **measured
baseline % = produced / catalog** (replaces the 15–20% estimate). **AC:** emits a per-cloud coverage
report; prints the real baseline. **Test:** harness runs in CI; baseline recorded.

### NEX-408 — Adversarial re-review of the 10 built families (MOVED earlier) — M ★ was Sprint-4
Red-team each shipped family (precision traps, the O(n²) `POD_CAN_REACH`, key convergence) **before**
S1–S3 build on them. **AC:** each family has a hardened bank; any bug fixed. **Test:** the new traps.

### NEX-004 — Wiring-foundation spike (1 day) + per-agent feed gaps — M ★ dormancy keystone
Design the **fixture-driven operating path**: a runner driving real agent `run()`s against a planted
fixture → shared graph → report card (extends `correlation.py`). **Verified caveat:** run() feed support
is NOT uniform — data-security/network/k8s/cloud-posture/vulnerability accept feeds; **identity + appsec
need a fixture-feed param added to `run()`** (sub-tickets 004a/004b). **AC:** documented seam + ONE agent
end-to-end through it + the per-agent feed-gap list. **Test:** e2e fixture → run() → graph → card.

---

## SPRINT 1 — SEAM A (contract) + dead agents (Days 4–10)

### NEX-101 — Canonical key builders for all resource types — L
As v1, plus **AC: guarded by NEX-002 regression lock** (existing paths byte-identical).
**Test:** per-builder unit + two-agents-same-resource-same-key unit.

### NEX-102 — Refactor agents onto canonical builders (regression-gated) — M
**Depends:** 101, 002. **AC:** no hand-built resource keys; **NEX-002 regression suite green after**
(this is the ticket most likely to break existing paths — the lock is mandatory).
**Test:** AST/grep guard (no literal resource-key construction) + full regression suite.

### NEX-103 — Cross-agent convergence guard test — M ★
3 agents at one fixture resource → one node. Trap: a mis-keyed agent makes it FAIL. (unchanged from v1)

### NEX-104 — multi-cloud-posture → path sources (multi-cloud parity) — M
Azure/GCP public resources get `is_public` (source-marking), keyed canonically → they feed paths.
**+ wired into run() (NEX-004 pattern).** **Test:** bank + e2e (Azure + GCP public → data path).

### NEX-105 — compliance = findings-only, formalized — S
`NON_PATH_AGENTS` registry + test asserting compliance is excluded BY DESIGN (no fake edge). (unchanged)

### NEX-106 — Seam C: single path entry point — S ★ was missing
Fold `find_all` + generic into ONE public entry (the report card is already it) and add a test that any
"all paths" consumer goes through it, so no caller can miss the moat paths. **Test:** guard test.

---

## SPRINT 2 — GRAPH GAPS: spike the hard ones, then unblock (Days 11–17)

### NEX-201 — `BINDS` traversable (K8s RBAC edge) — S
Add `BINDS` to traversable; bound role carries `is_admin` (already computed). **Test:** taxonomy + walk.

### NEX-202-SPIKE — KMS/DB-as-sink design (1 day) — M ★ (was a mis-sized L)
**Verified problem:** `walk_paths` matches sinks by **entity-type category** in a recursive CTE, not by
property. **Verified cascade:** KMS is written by cloud-posture as `CLOUD_RESOURCE{kind:kms-key}`;
changing it to the `KMS_KEY` category **orphans identity's `HAS_ACCESS_TO`→KMS edge** (record_access
writes CLOUD_RESOURCE). Evaluate: (a) **property-predicated sink** — extend the CTE to also stop at
`CLOUD_RESOURCE` nodes with a sink-property (no category change, no cascade — leaning this); (b) KMS_KEY
category migration + make `record_access` category-aware. **Output:** ADR + firm estimate + the cascade
resolution. **DoD:** an ADR, not code.

### NEX-202-IMPL — KMS/DB sinks (per spike) — size TBD by spike
Implement the chosen design + migration. **AC:** KMS-key/DB terminal paths surface; **NEX-002 regression
green** (existing `exposed_kms_key` path unchanged). **Test:** bank (match_sink) + e2e + regression.

### NEX-203 — Depth-strategy spike + fix — M ★ was missing (depth-4 ceiling)
**Verified problem:** new families (K8s-RBAC pod→SA→BINDS→admin→…→data) exceed 4 hops → won't emerge.
Decide: bump depth (measure CTE cost), or **path-stitching** (join sub-paths at shared nodes), or
per-family `max_depth`. **Output:** design + the perf numbers. Then implement the chosen fix.
**Test:** a 6-hop fixture path emerges under the new strategy; walk-cost benchmark within budget.

---

## SPRINT 3 — MOAT BREADTH: families + their real prerequisites (Days 18–25)

*Each family = its DETECTION prerequisite (if any) + the edge + bank + e2e + run()-wiring.*

### NEX-301 — K8s RBAC privilege escalation — M
**Depends:** 201, 203(depth). pod → SA → `BINDS` → admin ClusterRole → (IRSA cloud role → data).
**Test:** bank (admin-bound vs viewer-bound); e2e full chain; wired.

### NEX-302 — VPC-peering / routing lateral (`PEERED_WITH`) — L
Detector + traversable + wired. **Test:** bank (peered vs not; no transitive by default); e2e.

### NEX-303-DETECT — DB-contents data classification (prerequisite) — M ★ was hidden
No agent classifies DB data today. Add DB-level data classification (sample-based, like S3) so a DB can
`EXPOSES_DATA`. **Test:** bank; DB node gets a `DATA_CLASSIFICATION`.

### NEX-303 — Exposed-database source family — M
**Depends:** 303-DETECT, 202-IMPL. public DB `EXPOSES_DATA` → source→sink. **Test:** bank + e2e + wired.

### NEX-305-DETECT — SBOM package production (prerequisite) — M ★ was hidden
The vulnerability agent produces `SBOM_PACKAGE` nodes + `CONTAINS_PACKAGE` (image→package) +
package `VULNERABLE_TO` CVE. **Test:** bank; SBOM nodes on the graph.

### NEX-305 — Supply-chain SBOM vuln family — S
**Depends:** 305-DETECT. `workload → RUNS_IMAGE → image → CONTAINS_PACKAGE → package → VULNERABLE_TO`.
Names the vulnerable dependency. **Test:** e2e names the package; wired.

### NEX-304-SPIKE — CI/CD-compromise source (reverse-edge) — M ★ was a fake "M"
This is the W5 directionality problem, honestly a spike: design the forward code→cloud attack edge
(repo/build compromise → deployed resource → data) without fighting the walker. **Output:** ADR + go/no-go.
(Impl only if the spike says it's clean; otherwise it stays deferred — no lipstick.)

---

## SPRINT 4 — PARITY, DEPTH, OUTPUT, RE-MEASURE (Days 26–30)

### NEX-401 — `CAN_REACH` on Azure NSG + GCP firewall (parity) — M — bank+e2e+wired
### NEX-402 — Privesc method depth Azure+GCP (2–3 real methods each) — M — bank per method
### NEX-403 — Exploitability-weighted ranking (severity × KEV/exposure × blast-radius) — M ★ deterministic, not Bayesian
### NEX-404 — Blast-radius sizing per card (bounded neighbor count) — M
### NEX-405 — Evidence/"why" per card (render the edge chain) — S
### NEX-407 — POD_CAN_REACH O(n²) fix (source-pod-only emission) — S ★ was missing (my own ponytail flag)
### NEX-408 — Adversarial re-review of the 10 built families — M ★ was missing (harden what shipped)
### NEX-003b — RE-MEASURE coverage (the honest exit number) — S — the real % after 30 days

---

## Corrected sequencing (dependencies real this time)

```
S0  001(land) → 002(lock) → 003(measure baseline) → 004(wiring seam)
S1  101 → 102(gated by 002) → 103(guard) ; 104(wired) ; 105 ; 106(Seam C)
S2  201(BINDS) ; 202-SPIKE → 202-IMPL ; 203-SPIKE→fix (depth)
S3  301(needs 201,203) ; 302 ; 303-DETECT→303(needs 202) ; 305-DETECT→305 ; 304-SPIKE
S4  401 402 403 404 405 407 408 ; 003b(re-measure)
```

## Honest exit criteria (no fabricated numbers)

- Seam A contractual + convergence guard green (silent-join class closed).
- Dead agents resolved; **no new family lands test-only** (all wired via NEX-004).
- Coverage: baseline measured (003) → re-measured (003b). **Target is whatever the harness reports** —
  we commit to the *process*, not a made-up 40%.
- 2 spikes resolved (KMS/DB, depth) with ADRs; CI/CD spike go/no-go decided.
- Regression lock (002) green throughout; substrate changes migration-safe.

## What v2 added that v1 missed
Sprint 0 (land+measure+lock) · run()-wiring in every family (dormancy fix) · 2 spikes for the hard
unknowns · hidden detection prereqs (303-DETECT, 305-DETECT) · depth-strategy ticket · Seam C fix ·
O(n²) fix · existing-family hardening · regression + substrate safety · instrument-first (no fake %).

## Still explicitly OUT (drift guard)
❌ Remediation linkage · ❌ live cloud · ❌ Bayesian ranking · ❌ DSPy · ❌ Phase-0 v2.0 graph · ❌ new sensors.
