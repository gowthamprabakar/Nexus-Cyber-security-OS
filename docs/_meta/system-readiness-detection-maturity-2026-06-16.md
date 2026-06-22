# System Readiness Report — Detection Layer Maturity (v0.1 → v0.4)

**Date:** 2026-06-16
**Scope:** Full detection-layer maturity across all released milestones (v0.1, v0.2, v0.3) and the in-flight v0.4.
**Grounding:** Repo state at `main 6360079`; current branch `docs/v0-4-stage-1-6-appsec-brainstorm`. Coverage % are documented planning estimates, not instrumented measurements (v0.4 adds the instrumentation).

---

## 0. Executive Summary

| Version  | Status                                                      | Detection posture                                                     | Weighted coverage `[estimate]` |
| -------- | ----------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------ |
| **v0.1** | CLOSED (~2026-05)                                           | Offline / fixture-based; 5 agents; AWS-only; deterministic            | ~56–60%                        |
| **v0.2** | CLOSED 2026-06-14                                           | 17 agents live for their domain; multi-cloud; first LLM-heavy agents  | ~68–72%                        |
| **v0.3** | **OPERATING** 2026-06-15 (`main 6360079`)                   | Continuous-loop wiring load-bearing; +AppSec (D.14); fleet graph live | ~75–80%                        |
| **v0.4** | **ON HOLD** (directive draft v2, operator approval pending) | Depth-first agent maturity + fleet-graph (SemanticStore) extension    | **hard 85% target**            |

**Headline:** The fleet is at **18 agent packages, 17/17 at v0.2+ and OPERATING under v0.3.** The detection layer is real and live, not scaffolding — invariants, OCSF emission, and live readers are load-bearing. The remaining gap to "Wiz-parity" is **depth + correlation**, which is exactly what v0.4 targets. v0.4 is **blocked on operator sign-off**, not engineering.

---

## 1. The Fleet (18 packages) — Current Detection Roles

| Agent                         | Ver   | OCSF         | Live readers                      | Role                                               |
| ----------------------------- | ----- | ------------ | --------------------------------- | -------------------------------------------------- |
| **cloud-posture** (F.3)       | 0.2.0 | 2003         | AWS (boto3/Prowler)               | CSPM — AWS posture (reference NLAH)                |
| **multi-cloud-posture** (D.5) | 0.2.0 | 2003         | Azure + GCP                       | CSPM — Azure/GCP posture                           |
| **data-security** (D.5)       | 0.2.0 | 2003         | S3 + Azure Blob + GCS             | DSPM — data discovery + classification             |
| **k8s-posture** (D.6\*)       | 0.2.0 | 2003         | Kubernetes                        | CIS-bench + Polaris + manifest analysis            |
| **compliance** (D.6)          | 0.2.0 | 2003         | offline (consumes 2003)           | CIS/SOC2/PCI/HIPAA mapping + PASS attestation      |
| **vulnerability** (D.1)       | 0.2.0 | 2002         | Trivy + ECR/ACR/GCR               | Container CVE + OSV/EPSS                           |
| **identity** (D.2)            | 0.2.0 | 2004         | AWS IAM + Azure AD (Graph)        | CIEM + SAML/OIDC federation                        |
| **runtime-threat** (D.3)      | 0.2.0 | 2004         | Falco + Tracee + OSQuery          | CWPP real-time alert normalizer                    |
| **network-threat** (D.4)      | 0.2.0 | 2004         | Suricata/Zeek + VPC Flow          | Network IDS + DNS/DGA                              |
| **threat-intel** (D.8)        | 0.2.0 | 2004         | NVD + CISA KEV + feeds            | CTI correlation (STIX/TAXII)                       |
| **synthesis** (D.13)          | 0.2.0 | 2004         | LLM + offline sources             | LLM-narrated cross-agent synthesis                 |
| **curiosity** (D.12)          | 0.2.0 | 2004         | LLM-only (DeepSeek→Anthropic)     | Generative gap/hypothesis emission                 |
| **investigation** (D.7)       | 0.2.0 | 2005         | offline orchestrator (13 sources) | Incident correlation (orchestrator-workers)        |
| **remediation** (A.1)         | 0.2.0 | 2007         | Kubernetes                        | Safety-critical action (recommend/dry-run/execute) |
| **audit** (F.6)               | 0.2.0 | 6003         | append-only log                   | Hash-chained tamper-evidence (always-on)           |
| **supervisor** (#0)           | 0.2.0 | —            | —                                 | Declarative router + parallel dispatcher           |
| **meta-harness** (A.4)        | 0.2.5 | —            | —                                 | Cross-agent eval, NLAH A/B, DSPy cadence           |
| **appsec** (D.14)             | 0.1.0 | (2003 route) | GitHub/GitLab/Bitbucket           | SCM discovery + IaC/SAST/secrets-in-code           |

**OCSF emitter census:** 6× **2003** (compliance findings), 6× **2004** (detection findings), 1× **2002** (vuln), 1× **2005** (incident), 1× **2007** (remediation), 1× **6003** (audit). 3 non-emitters by design (supervisor, meta-harness orchestration; appsec still v0.1 substrate).

**Live vs offline:** ~10 agents carry live cloud/sensor/registry readers; the rest are aggregators, orchestrators, or LLM-only by design.

---

## 2. Version-by-Version Maturity

### v0.1 — Foundations (CLOSED)

- **Substrate F.1–F.6:** Charter (runtime contract + budget + audit chain), eval framework, F.3 reference agent, auth/tenants, memory engines (pgvector/LTREE/semantic), F.6 audit.
- **Detection agents (5):** F.3 Cloud Posture, D.1 Vulnerability, D.2 Identity, D.3 Runtime, F.6 Audit.
- **Character:** Offline/fixture-based, deterministic (no LLM in loop), single-cloud (AWS), ~10 eval cases/agent.
- **Coverage `[estimate]`:** CSPM 84% · Network 80% · CWPP 50% · CIEM 30% · DSPM 25% · Threat-Intel 25% · Vuln 20% · AppSec/AI-SPM **0%**. **Weighted ~56–60%.**

### v0.2 — Detection Build-Out (CLOSED 2026-06-14)

- **All 17 agents complete**; each moved offline → **live for its domain**. 16 self-merge cascades; full fleet to v0.2.
- **New capability classes:** multi-cloud CSPM (Azure/GCP), live DSPM, live CIEM (Azure AD), CWPP real-time subscription (Falco/Tracee), network live (VPC flow), CTI live feeds; **first LLM-heavy agents** (synthesis D.13, curiosity D.12, investigation D.7).
- **Institutional patterns:** ADR-007 reference NLAH (v1.0→v1.6), LLM-adapter + NLAH-loader hoisting, OCSF emitter expansion, A.1's **10 safety invariants**, F.6 hash-chain.
- **Honest limitations at close:** `assert_*` invariants authored but **not yet wired into run() loops** (deferred to Phase C); some "live" capability sat in unregistered `*_live.py` modules; LLM never exercised live in CI (FakeLLMProvider only).
- **Coverage `[estimate]`:** CSPM ~90% · Network ~90% · CWPP ~65% · CIEM ~50% · DSPM ~40% · Threat-Intel ~55% · Vuln ~55%; AppSec/AI-SPM still **0%**. **Weighted ~68–72%.**

### v0.3 — Live-Loop + OPERATING (DECLARED 2026-06-15, `main 6360079`)

- **Phase C wiring sprint:** all 17 agents' safety invariants + OCSF emission + tool-registry patterns are now **load-bearing**, not scaffolding (A.1 10/10; `PENDING_MIGRATION` empty).
- **Net-new agent:** **D.14 AppSec** (Track B, B-1) — SCM discovery + SAST/secrets.
- **Fleet graph live:** SemanticStore as live graph (agents write inventory via `kg_writer.py`); Charter per-tenant LLM cap + DeepSeek→Anthropic fallback.
- **Process proof:** **0 substrate violations across the whole lifecycle**; full repo 7339 pass / 0 fail.
- **Coverage `[estimate]`:** CSPM ~95% · Network ~92% · CWPP ~70% · CIEM ~70% · DSPM ~55% · Threat-Intel ~60% · Vuln ~65%; AppSec entering, AI-SPM/SaaS **0%**. **Weighted ~75–80%.**
- **Honest ceiling:** detection-only maturity does **not** reach full Wiz parity without (a) the v2.0 attack-path graph and (b) two net-new agents (D.10 SSPM, D.11 AI-SPM). That is the v0.4 thesis.

### v0.4 — Depth + Fleet-Graph (ON HOLD — directive draft v2)

- **Commitment:** **hard 85% coverage** at OPERATING (instrumented, not estimated) + 3-hop correlation. Graph foundation = **Postgres SemanticStore extended (Neo4j stays dormant)**.
- **Sequencing:** depth-first; ~22–30 weeks (~5–7 months).
- **Stage 1 (~8–12wk) — agent depth + inventory discovery + `kg_writer.py`:**
  - 1.1 D.3 Runtime — FIM + Falco/Tracee eBPF expansion + active anomaly + runtime inventory
  - 1.2 D.5 Data-Security — RDS + DynamoDB + BigQuery (Snowflake→v0.5) + DB inventory
  - 1.3 D.6 K8s — CIS v1.8→v2.0 + K8s inventory
  - 1.4 D.4 Network — `kg_writer` wiring + network-topology discovery
  - 1.5 D.2 Identity — gated per-role effective-perms depth + identity-hierarchy inventory
  - 1.6 D.14 AppSec — SAST expansion + multi-tenant scale + SCM repo inventory + code-to-cloud bridge _(current branch)_
- **Stage 2 (~8–12wk):** Hermes 2–5 (adjudication, skill-sharing, T2 trace persistence); **D.10 SSPM** (Salesforce/Slack/GitHub/Workspace/M365); **D.11 AI-SPM** (deployment discovery + prompt-injection via Garak/PyRIT).
- **Stage 3 (~4–5wk):** fleet-graph extension — codify inventory catalogue, wire all `kg_writer` outputs, 3-hop blast-radius/attack-path queries, findings-as-decorations migration.
- **Stage 4 (~1–2wk):** Wazuh 12-item enrichment (operator spec).
- **Stage 5 (~1–2wk):** v0.4 close + v0.5 readiness audit.

---

## 3. v0.4 Readiness — What's Done vs Blocked

**Ready:**

- Directive draft v2 recon-verified against `main 6360079`.
- **6/6 Stage 1 brainstorms + Stage 3 design brainstorm drafted** (`docs/superpowers/plans/2026-06-16-stage-1-*` + `stage-3-fleet-graph-design`).
- Key decisions locked: Postgres-not-Neo4j; inventory folded into Stages 1+2; Snowflake→v0.5; D.11 scope = deployment discovery + prompt-injection; D.5 naming collision resolved (data-security keeps D.5, multi-cloud-posture renames).

**Blocked / pending operator:**

- 🛑 **No v0.4 PRs until directive approved.**
- **Inventory catalogue (D-16): NOT RECEIVED** — blocks Stage 3 land (design can proceed in parallel). Pause trigger #46.
- **Wazuh 12-item spec** — due ~Week 18–22.
- **Open decisions:** R-1 catalogue D-numbering reconciliation; R-2 per-tenant credential store in-scope vs defer (safety-critical substrate).

**Risk register highlights:** R-1 coverage instrumentation needed for _hard_ 85% (HIGH); R-2 catalogue completeness/receipt (HIGH); R-8 velocity dilution — structural work ≠ cascade work (MED).

---

## 4. Detection-Capability Gap Map (toward 85%)

| Capability                   | v0.3 now `[est]` | v0.4 target driver                              |
| ---------------------------- | ---------------- | ----------------------------------------------- |
| CSPM (AWS/Azure/GCP)         | ~95%             | Mature — marginal                               |
| Network IDS                  | ~92%             | `kg_writer` topology wiring                     |
| CIEM                         | ~70%             | per-role effective-perms depth (1.5)            |
| CWPP                         | ~70%             | FIM + eBPF + active anomaly (1.1)               |
| Vulnerability                | ~65%             | (supply-chain → v0.5)                           |
| Threat Intel                 | ~60%             | active-campaign tracking                        |
| DSPM                         | ~55%             | RDS/DynamoDB/BigQuery (1.2)                     |
| Compliance                   | ~100%            | mature                                          |
| **AppSec (D.14)**            | entering         | SAST depth + code-to-cloud (1.6)                |
| **SSPM (D.10)**              | **0%**           | net-new agent (Stage 2)                         |
| **AI-SPM (D.11)**            | **0%**           | net-new agent (Stage 2)                         |
| **Cross-domain correlation** | partial          | **fleet-graph 3-hop (Stage 3)** ← biggest lever |

The two **0% buckets (SSPM, AI-SPM)** and the **correlation lever (Stage 3 graph)** are where v0.4's coverage gain concentrates — not in squeezing the already-mature posture agents.

---

## 5. Bottom Line

- **Built and OPERATING:** an 18-agent detection fleet at v0.3, with live readers, OCSF emission across 6 event classes, hash-chained audit, safety-critical remediation, and a live fleet graph — all load-bearing, with a clean substrate-violation record across the whole lifecycle.
- **Honest maturity:** ~75–80% weighted coverage `[estimate]`; the gap to parity is **depth + correlation + two missing domains (SSPM, AI-SPM)**, not breadth of the existing fleet.
- **Next step is a decision, not code:** v0.4 is fully scoped and brainstormed but **HELD on operator approval of the directive and delivery of the inventory catalogue.** Unblocking those starts the path to a hard, instrumented 85%.

---

### Reference files

- `docs/_meta/v0-4-directive-2026-06-16.md` — full v0.4 scope/stages/calendar/risks
- `docs/_meta/agent-detection-maturity-v0-1-to-v0-3-2026-06-07.md` — coverage trajectory + Wiz comparison
- `docs/_meta/v0-2-quality-audit-2026-06-13.md` — v0.2 depth audit
- `docs/_meta/decisions/ADR-001..017` — architecture decisions (ADR-007 reference NLAH)
- `docs/superpowers/plans/2026-06-16-stage-1-[1-6]-*-brainstorm.md` + `stage-3-fleet-graph-design-brainstorm.md`
