# Destination Roadmap Analysis — where we are (2026-07-02)

A full state-of-the-project across every layer of the value chain. Grounded in the codebase, not memory.

## The destination (unchanged)

A customer connects a cloud account and within minutes sees their **top ~10 real attack paths,
prioritized, each with a fix**, at a measured **~50–60% of Wiz value**. The moat is the **Security
Graph** (correlation into attack paths) — NOT the scanners, which are commodity.

## The value chain (the pipeline every finding travels)

```
Detection → Graph (nodes+edges) → Attack-Path (correlation) → Prioritized Output → Remediation → Live/Continuous
   sensors      the substrate         THE MOAT                  the report card       the fix        operating
```

---

## Layer-by-layer status

### 1. DETECTION (the sensors) — ✅ breadth mostly built, AWS-skewed
- **20 agents** in the fleet, all at v0.2+; Stage 2 net-new **SSPM (SaaS)** + **AI-SPM** added in v0.4.
- Backed by commodity OSS (Prowler / Trivy / Falco / kube-bench) + net-new detectors.
- **Coverage ~57–63%** (estimated, never instrumented — authoritative figure in the Phase-D readiness
  audit). Per-cloud: **AWS ~91%, Azure ~55%, GCP ~50%.**
- **Verdict:** breadth is largely there; **depth and multi-cloud parity are the gaps**, not sensor count.

### 2. GRAPH (the moat substrate) — ✅ foundation done, filling in
- Postgres `SemanticStore`; **~72 edge types defined, 28 produced (have a writer), 21 traversable**;
  **14 source markers, 4 sink markers, 19 named path archetypes**.
- Substrate hardened: cross-run edge dedup (ADR-022), 3-hop `kg_query`, live-Postgres proven, LTREE +
  tenant-RLS fixes.
- **Verdict:** substrate **DONE**. Edge coverage is ~15–20% of the full kill-chain arc (see §3).

### 3. ATTACK-PATH (correlation — THE MOAT) — 🟡 core engine done, breadth growing fast
- **Named archetypes (19)** + the **generic engine** (`find_candidate_paths`: multi-source BFS, novelty-
  filtered against named shapes, depth-4).
- **Edge families built (this arc took the moat from ~0% to ~10 families):**
  privilege escalation (`CAN_ESCALATE_TO`, 3 clouds) · network lateral (`CAN_REACH`) · K8s pod lateral
  (`POD_CAN_REACH`) · container escape → cloud (`USES_SERVICE_ACCOUNT`+`IRSA_MAPPING`) · leaked-credential
  blast radius (`OWNED_BY`, **3 clouds**) · stored-secret (`STORES_SECRET`) · cross-account trust (`ASSUMES`).
- **Verdict:** engine + ~10 families **built and proven**; the complete arc is ~7 kill-chain stages × up
  to 4 clouds ≈ **25–40 edge-implementations → we are ~15–20%.**

### 4. PRIORITIZED OUTPUT (the report card) — ✅ v1 built (this session)
- `build_report_card` merges named + novel paths into one worst-first ranked list, dedups, and attaches a
  **fix per path**; `render_tenant_report_card` is the single entry point.
- Polish: readable ARNs (C1), access-leg subsumption (C2).
- **Verdict:** the North-Star sentence is **proven end-to-end** (a planted multi-finding tenant → ranked
  card with fixes, no cloud account). This is v1; ranking is severity-table-based, not yet Bayesian.

### 5. REMEDIATION (the fix) — 🟡 agent exists, NOT linked to paths
- The **A.1 remediation agent** is built (v0.2): one-click S3/RDS/KMS + K8s patch, 10 safety invariants
  (dry-run-first, mandatory rollback, blast-radius ceiling, tool-proxy, tenant-scoped).
- The report card carries **fix HINTS** (path_type → remediation string), **NOT wired to the live
  remediation agent** — a deliberate roadmap decision (the moat is the graph, not the fix engine).
- **Verdict:** remediation **capability exists**; the path → one-click-fix **linkage is not built** (deferred).

### 6. LIVE WIRING / CONTINUOUS LOOP — 🔴 the biggest structural gap
- Most detectors are **test-proven but not wired into `run()`** against live/fixtures; live lanes are
  operator-gated (`NEXUS_LIVE_*`) and the operator has no cloud account.
- **Run-wired today:** identity escalation + access, cross-account trust (W3). The K8s/stored-secret/etc.
  edges write via existing writer calls or are detector-proven only.
- Continuous-loop **foundation** exists (Track D) but is not the operating default.
- **Verdict:** the gap between **"tested" and "operating"** is the single largest remaining structural item.

---

## The verticals we planned (multi-track history)

| Track / phase | What | Status |
|---|---|---|
| v0.1 → v0.2 | 17-agent fleet to v0.2 (16 cycles) | ✅ closed |
| v0.3 Track A | live-loop + depth | ✅ operating |
| v0.3 Track B | discovery engine (BP1–BP8, generic path engine) | ✅ done |
| v0.3 Track C | DSPy meta-harness cadence + Hermes | ✅ phases done; production default-OFF |
| v0.3 Track D | continuous-loop foundation | 🟡 foundation only |
| v0.4 Stage 2 | net-new SSPM (SaaS) + AI-SPM agents | ✅ done |
| v0.4 Fleet-test | L1 integration smoke + L2 banks | ✅ L1 done; L2 partial |
| **Moat pivot** | graph-first, one-edge-at-a-time correlation | 🟡 **in progress (this arc)** |

---

## Where we are — one paragraph

**Detection breadth is largely built** (20 agents, ~57–63% coverage, AWS-skewed). **The graph substrate is
done.** This arc took **the moat — attack-path correlation — from essentially 0% to ~10 real path families
plus a customer-facing report card** that proves the North-Star sentence end-to-end. **Remediation exists
but is unlinked**, and **live-wiring (tested → operating) is the biggest remaining structural gap.** We are
roughly **15–20% through the full attack-path arc**, with the highest-value real-breach paths done first.

## What is NOT completed (the honest gap list, ranked by leverage)

1. **Live wiring / continuous operating loop** — detectors mostly not `run()`-wired; no default operating
   loop. This is why the moat is "proven" not "operating."
2. **Attack-path arc breadth** — ~80% of kill-chain edges remain: missing **sources** (CI/CD, exposed-DB,
   serverless), missing **sinks** (KMS/DB/model-poison — blocked by the walker's node-category design),
   **network topology** (VPC peering/routing), **supply-chain** (`BUILT_FROM` = provenance, needs a
   reverse-edge model).
3. **Remediation linkage** — report card → live one-click fix not built (deferred by decision).
4. **Multi-cloud parity** — Azure/GCP behind AWS on depth; several edges are AWS-first with readers deferred.
5. **Coverage never instrumented** — all figures are estimates; no measured denominator.
6. **Depth items** — Bayesian path ranking, effective-perms simulator built-but-undriven, per-cloud method
   depth (privesc has 5 AWS methods, 1 each Azure/GCP).
7. **v0.4/v0.5 backlog** — DSPy production flip (Gate 3), fleet-test L2 banks, Phase-0 v2.0 graph (the only
   path past the ~75–80% coverage ceiling), meta-harness continuous cadence.

## Recommended next destination (from here)

The moat pivot is the right North-Star work. The two highest-leverage moves:
- **Make it operate** (Theme B): wire the built edges into a fixture-driven run loop → the graph builds on a
  real run, not just tests. This converts "proven" into "operating."
- **Keep the edge flywheel** (the arc): the next real-breach families, AWS-first then across clouds — but
  only after (or alongside) wiring, so nothing new goes dormant.

Remediation linkage and coverage instrumentation are valuable but secondary to graph + operation.
