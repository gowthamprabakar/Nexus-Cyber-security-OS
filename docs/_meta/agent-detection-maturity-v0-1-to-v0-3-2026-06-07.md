# Agent Detection-Maturity Report — v0.1 → v0.3 vs Wiz + Our Plan (2026-06-07)

> **What this is.** The detection layer's maturity trajectory: where each detection agent is **today (v0.1)**, where **our plan** takes it at **v0.2** and **v0.3**, the **Wiz target** in that category, and the **residual gap at v0.3**. Then the honest verdict: does executing detection to v0.3 reach Wiz parity?

- **Scope:** the **detection** agents only — the ones that produce findings (F.3, D.1, D.2, D.3, D.4, D.5 multi-cloud, D.6 k8s, D.8, Data-Security/DSPM, Compliance, F.6 audit). The reasoning/cure/meta agents (D.7, D.12, D.13, A.1, A.4, Supervisor) are out of scope here.
- **Sources:** current state from [capability-vs-Wiz](agent-capability-vs-wiz-2026-06-07.md) (PR #242) + [platform readiness](nexus-platform-readiness-2026-06-07.md) (PR #241); the plan from [`agent-version-roadmaps`](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md). Wiz column = industry-known. Coverage %s are **estimates** extending the readiness-report methodology.
- **One-line answer:** executing detection v0.1 → v0.3 takes the platform from **~56–60% → ~75–80% weighted Wiz coverage** — it closes _offline→live_ and most _breadth/multi-cloud_ gaps, but it **does not reach Wiz parity**, because two whole categories have **no agent** (AppSec, AI-SPM/SaaS) and Wiz's signature **attack-path / toxic-combination graph is a v2.0 substrate, not detection-agent maturity.**

---

## 1. The detection maturity ladder (per agent)

Legend: ✅ shipped · ⬜ planned. "Residual gap @ v0.3" = what still separates us from Wiz after the plan executes.

| Agent                    | v0.1 (now)                                                                   | v0.2 (plan)                                                  | v0.3 (plan)                                                | Wiz target                                                            | Residual gap @ v0.3                                       |
| ------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------- |
| **F.3 Cloud Posture**    | Prowler offline + 3 boto3 checks; AWS; LocalStack                            | ⬜ **live boto3** + account autodiscovery                    | ⬜ 1,200+ patterns + cross-account + Organizations         | continuous agentless multi-cloud CSPM + config-graph                  | the **graph** (v2.0); agentless scale                     |
| **D.5 Multi-Cloud**      | Defender+SCC+Activity offline + ~5 GCP-IAM rules                             | ⬜ **live Azure/GCP SDK**                                    | ⬜ OCI                                                     | full Azure/GCP/OCI/Alibaba CSPM                                       | Alibaba; native-rule breadth                              |
| **D.6 K8s Posture**      | manifest + kube-bench/Polaris (✅ live kubeconfig + in-cluster already)      | ✅ shipped                                                   | ✅ shipped → ⬜ v0.4 100+ rules/CIS-full                   | KSPM+admission+RBAC+image+runtime-graph                               | RBAC inventory, admission webhooks                        |
| **D.1 Vulnerability**    | Trivy image CVE offline + KEV/EPSS/CVSS/OSV                                  | ⬜ **live registry** + image-pull policy                     | ⬜ malicious-package supply-chain                          | agentless vuln across VM/container/serverless/host + reachability     | **host/VM/serverless agentless**; reachability            |
| **D.3 Runtime Threat**   | Falco/Tracee/OSQuery Linux, fixtures                                         | ⬜ **Windows CWPP**                                          | ⬜ autonomous-kill → A.1                                   | runtime sensor + agentless, Linux+Windows + cloud-event correlation   | live sensors; macOS; cloud-event join                     |
| **D.4 Network Threat**   | port-scan/beacon/DGA + Suricata + static intel, offline                      | ⬜ **live VPC flow + Athena**                                | ⬜ Tor + cross-window beacon baselines (needs TimescaleDB) | network **exposure-path graph**                                       | the exposure graph (v2.0); live IOC depth                 |
| **D.2 Identity (CIEM)**  | AWS IAM: overprivilege/dormant/external/MFA-gap (attached-policy admin only) | ⬜ **Azure AD/Entra**                                        | ⬜ GCP IAM + federation forensics                          | effective-permissions + identity-graph + lateral-movement, all clouds | **effective-perms** (inline/SCP/boundary); identity-graph |
| **Data Security (DSPM)** | S3 4 detectors + 7-label regex/Luhn, offline samples                         | ⬜ **live boto3** + classifier expansion + Macie             | ⬜ RDS + DynamoDB                                          | DSPM across many stores + ML classify + data-flow graph               | multi-store breadth; ML; toxic-combination                |
| **D.8 Threat Intel**     | 3 offline feeds; IOC index CVE-only                                          | ⬜ **live HTTP + MISP/TAXII + abuse.ch/VT** (populates IOCs) | ⬜ active-campaign tracking                                | integrated TI + exploitability across the graph                       | graph-integrated exploitability                           |
| **Compliance**           | CIS-AWS, 12 of 43 controls wired, FAIL-only                                  | ⬜ **SOC2/PCI/HIPAA/NIST** + PASS attestation                | ⬜ drift detection (needs TimescaleDB)                     | 100+ frameworks, continuous, multi-cloud                              | multi-cloud framework mapping; continuous drift           |
| **F.6 Audit**            | hash-chain tamper + 5-axis query (**Nexus-ahead**)                           | ⬜ cross-tenant alerting                                     | ⬜ isolation harness + external timestamp                  | activity/audit search                                                 | none material — Nexus-ahead on integrity                  |

**Two categories have no agent and therefore no maturity ladder:** **AppSec / IaC / secrets-in-code / CI** and **AI-SPM / SaaS posture (SSPM)**. These are **0% at v0.1 and stay 0% through v0.3** — they require _net-new agents_, not version maturity.

---

## 2. Category coverage trajectory (estimated weighted Wiz %)

Extends the readiness-report Wiz table. v0.1 = measured/cited; v0.2/v0.3 = **estimates** of what the planned deltas buy (live feeds + multi-cloud + breadth). Weights are the pinned Wiz weights.

| Category (weight)        |    v0.1 now | v0.2 (plan) | v0.3 (plan) |  Wiz | What lifts it                                                                  |
| ------------------------ | ----------: | ----------: | ----------: | ---: | ------------------------------------------------------------------------------ |
| CSPM (0.35)              |         84% |        ~90% |        ~95% | 100% | F.3 live + D.5 live + pattern breadth                                          |
| Vulnerability (0.13)     |         20% |        ~55% |        ~65% | 100% | live registry (v0.2); supply-chain (v0.3); **host/VM agentless still missing** |
| CIEM (0.09)              |         30% |        ~50% |        ~70% | 100% | Azure (v0.2), GCP+federation (v0.3); **effective-perms depth still partial**   |
| CWPP (0.09)              |         50% |        ~65% |        ~70% | 100% | Windows (v0.2); live sensors still gated                                       |
| DSPM (0.07)              |         25% |        ~40% |        ~55% | 100% | live+classifier (v0.2), RDS/Dynamo (v0.3); multi-cloud later                   |
| CDR/Investigation (0.06) |         85% |        ~88% |        ~90% | 100% | D.7 IOC pivoting (v0.3, needs D.8 live)                                        |
| Network (0.04)           |         80% |        ~90% |        ~92% | 100% | live flow (v0.2); exposure-graph is v2.0                                       |
| Compliance/Audit (0.04)  |        100% |        100% |        100% | 100% | saturated (breadth deepens under the row)                                      |
| Remediation (0.04)       |         50% |        ~60% |        ~65% | 100% | (cure track, not detection)                                                    |
| Threat Intel (0.03)      |         25% |        ~55% |        ~60% | 100% | live feeds (v0.2)                                                              |
| **AppSec (0.04)**        |      **0%** |      **0%** |      **0%** | 100% | **no agent — needs net-new**                                                   |
| **AI/SaaS (0.02)**       |      **0%** |      **0%** |      **0%** | 100% | **no agent — needs net-new**                                                   |
| **Weighted total**       | **~56–60%** | **~68–72%** | **~75–80%** | 100% |                                                                                |

**Read this honestly:** detection maturity to v0.3 buys roughly **+18–22 points** — most of it from flipping the offline agents to **live** and adding **multi-cloud**. The curve then flattens: the last ~20–25 points are **not** reachable by maturing the existing detectors.

---

## 3. The verdict — does v0.1 → v0.3 reach Wiz?

**No.** Detection maturity to v0.3 makes the platform _live, multi-cloud-partial, and broad on single-finding detection_ across the categories we cover — a real, demo-credible jump. But three things keep it short of Wiz, and **none of them are fixed by maturing the detection agents**:

1. **Two categories have no agent.** AppSec (SAST/DAST/IaC/secrets-in-code/SBOM-supply-chain) and AI-SPM/SaaS posture are 0% and have **no maturity ladder** — they need _new agents_. Together ~6% of the Wiz weight, plus they're table-stakes for a "full CNAPP" claim.
2. **The attack-path / toxic-combination graph is Wiz's signature — and it's a v2.0 substrate, not detection.** Even with every detector at v0.3, Nexus emits _individual_ findings; it does not compute exposure paths or toxic combinations. This isn't in the per-category weight model at all, yet it's the single biggest reason buyers choose Wiz. It comes from the **v2.0 security-graph layer**, orthogonal to detection maturity.
3. **Depth ceilings inside covered categories.** Wiz's _agentless_ vuln/workload scanning (no sensor, full host/VM/serverless) and _effective-permissions_ CIEM (inline+SCP+boundary across clouds) are architecturally deeper than our v0.3 plan reaches. Our v0.3 narrows these but doesn't match them.

**What v0.3 detection-complete _does_ buy (real and worth stating plainly):**

- The offline→live transition across ~9 agents → **continuous, real-environment detection** (the single most demo-credible change).
- **Multi-cloud** CSPM/CIEM/DSPM (Azure+GCP joining AWS).
- **Live threat-intel** populating real IOCs → meaningfully better D.4/D.3/D.7 correlation.
- A defensible **~75–80% weighted Wiz coverage** — strong for a platform this young, and honest.

**The plain framing for strategy:** detection v0.1→v0.3 is **necessary but not sufficient** for Wiz parity. After it, the gap to Wiz is **(a) two net-new agents** (AppSec, AI/SaaS) and **(b) the v2.0 attack-path graph** — not more detector tuning.

---

## Appendix — method + caveats

- v0.1 figures: measured/cited (readiness report + capability doc). v0.2/v0.3 figures: **estimates** of planned deltas; no post-v0.2 measured snapshot exists.
- "Live breadth unproven": the wrapped tools (Prowler/Trivy/kube-bench/Falco) carry rule breadth, but v0.1 only exercises them on **offline fixtures** — the v0.2 live step is what _realizes_ that breadth.
- D.6 K8s already shipped its v0.2 (kubeconfig) + v0.3 (in-cluster) live paths; its next lift is rule-breadth (v0.4).
- F.6 Audit is the one detection-category where Nexus is **ahead** (hash-chained tamper detection).
- Cross-cutting blocker for the whole live step: a **live-cloud credential/sandbox substrate** that does not yet exist (flagged in PR #241); multi-tenant additionally blocked on the SET LOCAL tenant-RLS bug.
