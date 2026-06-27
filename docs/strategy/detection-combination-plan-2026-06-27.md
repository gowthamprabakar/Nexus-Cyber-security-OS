# Plan: Finishing Detection + the Combination (Tracks A & B)

**Date:** 2026-06-27 · **Status:** Track A in progress. Facts grounded in repo at `fleet-test-l2-evaluator`.

> **✅ A1 BUILT (commit b41d0d7):** first cross-domain path — "owned resource communicating with a known-malicious IP" (network + threat-intel). The deferred Stage-3 bridge resolvers are now real (`meta_harness.correlation`: `link_ip_ownership` → `OWNED_BY`, `link_threat_indicators` → `MATCHES_INDICATOR`); cloud-posture EC2 captures `private_ips`; new `malicious_destination` archetype (sev 85) with grouping + remediation + render; moto-REAL e2e. **threat-intel wrote its first graph edges; the IP→resource join is built.** This proves the resolver pattern A2/A3 reuse. Next: A2 (runtime `RUNS_ON`) or A3 (code-to-cloud).

Answers the question: _"Have we finished the detection modules and their combination?"_ — **No.** This lays out exactly what's combined, what isn't, why, and the plan to finish it. We discuss and decide before building.

---

## 1. Facts — what is actually "combined" today

The attack-path engine (`meta_harness.kg_query` 9 detectors + `AttackPathRanker`) is **the combination**. It consumes **6 of ~40 node categories**: `CLOUD_RESOURCE`, `IDENTITY`, `DATA_CLASSIFICATION`, `CVE_FINDING`, `K8S_OBJECT`, `AI_SERVICE`. Everything else is produced but never correlated.

**Per-agent graph state (verified in code):**

| Agent                                                                     | Has kg_writer? | Writes to graph TODAY                                                 | Bridge edge to the spine                                                                                        | Status               |
| ------------------------------------------------------------------------- | -------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------- |
| data-security, identity, vulnerability, cloud-posture, k8s-posture, aispm | yes            | the 6 combined node types + their edges                               | — (already feeders)                                                                                             | ✅ combined          |
| **network-threat** (D.4)                                                  | yes            | `CLOUD_RESOURCE`(IP as `kind=network-endpoint`) + `COMMUNICATES_WITH` | **IP → owning cloud resource** — explicitly deferred ("Stage 3, not this writer", kg_writer.py:10)              | ❌ not combined      |
| **runtime-threat** (D.3)                                                  | yes            | `PROCESS_EVENT`, `FILE_INTEGRITY_EVENT`, host node + `EXECUTED_ON`    | **host-uid → cloud resource** — depends on upstream collection; no normalizer                                   | ❌ not combined      |
| **threat-intel** (D.8)                                                    | yes            | `ioc`/`cve`/`ttp` entities, **NO EDGES**                              | **IOC → resource/finding** — correlator joins are in-memory only, never graph-persisted                         | ❌ not combined      |
| **appsec** (D.14)                                                         | yes            | `CODE_REPOSITORY`, `IAC_ARTIFACT` + `DEFINED_IN`                      | **code → deployed resource** (`DEPLOYED_VIA`/`BUILT_FROM`) — deferred; AppSec can't reverse-map                 | ❌ not combined      |
| **sspm** (D.10)                                                           | yes            | `SAAS_TENANT`, `OAUTH_APP` + `AUTHORIZED`                             | **SaaS user/app → cloud identity** (`SSO_INTO`/`FEDERATED_FROM`) — needs federation-config collection, deferred | ❌ not combined      |
| **compliance**                                                            | yes            | `COMPLIANCE_FRAMEWORK`/`REQUIREMENT`, **no edges to findings**        | not a detector — meta/reporting layer; aggregates per-control (lossy, drops ARN)                                | ⛔ not a path feeder |

**The universal blocker (this is the whole story):** the bridge edge _types_ already exist in `graph_types.py` (`COMMUNICATES_WITH`, `EXECUTED_ON`, `OWNED_BY`, `RUNS_ON`, `DEPLOYED_VIA`, `SSO_INTO`, …). What's missing in **every** case is the **last-mile resolver** that populates them — the code that maps a domain's native key (IP, host-uid, IOC, repo, SaaS user) to a canonical `CLOUD_RESOURCE`/`IDENTITY` node. ADR-023 named this "mechanism-② bridge edges" and deferred all of it except `RUNS_IMAGE` (which we then proved REAL for path 2). So: **the vocabulary is done; the joins are not.**

---

## 2. Track A — wire the cold domains in (build the resolvers + cross-domain patterns)

Each cold domain becomes a feeder by building one resolver + one new hardcoded attack-path pattern (the proven Phase-1 approach). Ranked by **value × CI-REAL feasibility** (can we prove it with moto/kind, or is it operator-only?).

### A1 — Network + Threat-Intel via an IP→resource resolver _(two domains, one bridge)_

- **Attack paths unlocked:** "internet-exposed resource is **beaconing to a known-malicious IP**" (network flow dst_ip ∈ threat-intel IOC set) and "external scanner → exposed resource". Two domains light up from one resolver.
- **Bridge/resolver:** `OWNED_BY` (IP → instance/ENI). moto supports EC2 ENIs with private IPs, so a resolver mapping a flow IP → the instance that owns that ENI is **CI-REAL via moto**. Threat-intel then rides the same IP: write `MATCHES_INDICATOR` (flow → IOC) so a detector joins exposed-resource → malicious-IP.
- **Also needs:** threat-intel's kg_writer must start writing **edges** (today it writes entities only).
- **Feasibility:** REAL (moto). **Value:** high (active-threat signal on the exposure surface). **Effort:** medium.

### A2 — Runtime exploit on an exposed vulnerable workload _(the "live crown jewel")_

- **Attack path unlocked:** "a **runtime exploit event is firing ON** an internet-exposed workload running a vulnerable image" — detection + active exploitation on one pivot. The single most compelling demo path.
- **Bridge/resolver:** `RUNS_ON` (host-uid → workload). For K8s the host is a pod UID; a kind cluster gives real pod→node→workload mapping, so **CI-REAL via kind**. For VMs the host-id is an instance-id (trivial same-key join). The catch: runtime's `host_id` normalization depends on upstream collection — needs a defined contract for what `host_id` _is_.
- **Feasibility:** REAL for K8s (kind), operator-dependent for VMs. **Value:** highest. **Effort:** medium-high (host-id contract is the risk).

### A3 — Code-to-cloud: secret-in-code / IaC-misconfig → deployed resource

- **Attack path unlocked:** "a **secret committed in repo X** is the credential for **cloud resource Y**", or "an IaC misconfig deployed an exposed resource". Code-to-cloud is a genuine CNAPP differentiator.
- **Bridge/resolver:** `DEPLOYED_VIA`/`BUILT_FROM` (resource → repo/commit). The honest direction problem: AppSec knows the code, not the deployed target. The resolver must run from the **cloud side** — map a resource's git-sha/repo **tag** (moto resources can carry tags) back to the repo. **CI-REAL via moto resource tags.**
- **Feasibility:** REAL (moto tags), but depends on resources actually being tagged with provenance (real-world: inconsistent). **Value:** high (differentiator). **Effort:** medium.

### A4 — SSPM: over-scoped SaaS app → SSO into cloud identity _(feasibility-blocked)_

- **Attack path:** "an over-permissioned M365/Slack OAuth app can **SSO into a cloud identity**".
- **Bridge/resolver:** `SSO_INTO`/`FEDERATED_FROM` — needs federation-config collection (SAML/OIDC issuer → cloud account) cross-referenced against D.2's federated providers. **No moto for federation → operator-verified only, not CI-REAL.**
- **Recommendation:** **defer.** It can't meet the "Done = watched it work" bar without live tenants; building it now produces WIRED-not-REAL.

### A5 — Compliance _(not a path feeder)_

- It's a reporting/attestation layer that aggregates per-control and **loses the per-resource ARN**. It contributes nothing a path detector can join on. **Skip** as a feeder; at most it could re-contextualize a path's severity by framework, which is lossy. Not in scope.

**Track A honest feasibility summary:** A1, A2(K8s), A3 are **CI-REAL-able** (moto/kind). A2(VM) and A4 are **operator-verified at best**. A5 is out.

---

## 3. Track B — the generic Phase-2 path engine

**What already exists:** `KgQuery.attack_path(src, dst, edge_types, max_depth=3)` — a real depth-bounded BFS returning all simple paths, plus `blast_radius()`. Both are **tested but UNUSED in production** — the ranker runs the 9 hardcoded detectors instead. The substrate does multi-hop in-Python (`neighbors()`); a Postgres recursive-CTE is noted as "Phase 1b, not implemented." Depth cap = 3 everywhere.

**The key realization:** the 9 hardcoded detectors are each a **(exposure-source, edge-path, impact-sink) triple**. A generic engine would:

1. **Mark exposure sources** generically (`is_public=True`, `external_trust=True`, `privileged=True`, `allAuthenticatedUsers`, …) — today these are inline `if` checks scattered across detectors.
2. **Mark impact sinks** generically (sensitive `data_type`, CVE `severity≥HIGH`, …) — today `_SECRET_DATA_TYPES` etc. are hardcoded frozensets.
3. **BFS from each source to each sink** (the existing `attack_path()` already does this) and emit a path.
4. **Score** the path by composition (length + the severity labels of the nodes it crosses) — today severity is a hardcoded per-archetype dict.
5. **Dedup / group / subsume** — _we already built this_ in the ranker (group-by-subject + crown-jewel subsumption); it would be lifted into the engine.

**What's genuinely missing for B:** (1) the source/sink marking model, (2) a composable severity-scoring function, (3) wiring the existing BFS into the ranker. Cycle handling is done; dedup is done.

**The real risks of B (why it's a bigger bet):**

- **Combinatorial explosion / nonsense paths** — a generic walker finds paths a human would call meaningless; the hardcoded patterns are precise and explainable by construction.
- **Explainability** — "crown jewel" is a named, understood story; "source-12 → 4 hops → sink-7" is not. The render/remediation layers key on `path_type`; a generic engine emits arbitrary shapes.
- **Scoring is the hard part** — without per-archetype severities, ranking arbitrary paths credibly is unsolved.

---

## 4. The synergy and the sequencing decision

**A enables B.** A generic engine over today's 6-node-type graph finds _the same 9 paths_ — no new value. The generic engine's payoff scales with **how many domains are connected** (Track A). So:

- **B is premature today.** Build it now and it discovers nothing the hardcoded patterns don't.
- **A is the enabler and is independently valuable** — each bridge is a new REAL attack path on the board, and each resolver is exactly the join a future generic engine needs anyway.

**Recommended sequence:**

1. **Track A first** — build the resolvers + 2–3 new cross-domain patterns as hardcoded detectors (extending the proven, explainable Phase-1 approach). Order by feasibility: **A1 (IP / network+threat-intel) → A2 (runtime/K8s) → A3 (code-to-cloud)**. Defer A4 (operator-only), skip A5.
2. **Then Track B** — once the graph is rich (≥3 more domains connected) and we have a scoring model, evolve to the generic engine, lifting our existing dedup/subsumption logic and the unused `attack_path()` BFS. B becomes the multiplier that finds the _unanticipated_ combinations across the now-rich graph.

This matches the strategy memo ("moat = correlation; build the moat first") and keeps every step CI-REAL and explainable.

---

## 5. The first concrete slice (specified, NOT built)

**Slice 1 = A1, the IP resolver + the malicious-IP path** — best value-per-effort and unlocks two domains:

- Build an `ip_to_resource` resolver (moto EC2 ENI/instance lookup) → write `OWNED_BY` (IP `CLOUD_RESOURCE` → instance `CLOUD_RESOURCE`).
- Have threat-intel's kg_writer write `MATCHES_INDICATOR` (network flow/IP → IOC) — its first edges.
- New detector `find_exposed_resource_contacting_malicious_ip` in `kg_query` + a severity + a `path_type` in the ranker + remediation advice + render label.
- A moto+injectable e2e in the whole-environment style: an exposed instance with a flow to a seeded-malicious IP lights it up; a flow to a benign IP stays dark.
- **Verifies the resolver pattern** that A2/A3 reuse.

---

## 6. Open decisions (for discussion before any build)

1. **Sequence:** A-first (recommended) vs a thin B-prototype in parallel to de-risk the engine?
2. **First bridge:** A1 (IP, two domains, recommended) vs A2 (runtime, highest single value but host-id-contract risk)?
3. **Operator-only domains:** defer A4 (sspm federation) entirely, or build it WIRED-not-REAL and label honestly?
4. **Severity model for B:** when we get there, composable-scoring vs keep per-pattern severities and only use B to _discover_ candidates a human names?
5. **host_id contract (A2):** do we define a normalization contract for runtime `host_id`, or scope A2 to K8s-only first (kind-REAL)?

---

### Reference (file:line, verified)

- Combination consumes 6 node types — `meta_harness/kg_query.py` (the 9 `find_*` methods, ~293–645)
- Generic BFS exists/unused — `kg_query.py:243–291` (`attack_path`), `218–241` (`blast_radius`)
- Substrate traversal — `charter/memory/semantic.py:311–338` (`get_relationships_from`), `258–309` (`neighbors`)
- Bridge deferrals — `network_threat/kg_writer.py:10`, `appsec/kg_writer.py:7–13`, `sspm/kg_writer.py:15–19`; `ADR-023` mechanism-② (deferred)
- Bridge vocabulary already defined — `charter/memory/graph_types.py` (EdgeType enum)
