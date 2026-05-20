# Agent version roadmaps — lightweight per-agent v0.x maps (2026-05-20)

**What this is.** One short section per agent — 10 shipped + 7 unbuilt = 17 agents — covering: current shipped version, next planned version, subsequent versions visible from the PRD §7 capability spec, the terminal "enterprise-grade-complete" version, cross-agent version dependencies, and substrate / carry-forward debt gates per version.

**Why now.** Before committing v0.1 scope for D.5 Data Security (and the other 6 unbuilt agents), v0.1 needs to sit defensibly inside its own version trajectory. ADR-010 codifies the _shape_ of within-agent version extensions; no document maps the _content_ per agent. This is the lightweight content map.

**Discipline.** LOW-RISK doc-only per ADR-011. **HARD SCOPE FENCE: no code, no full plans, no started work, no revisions to the 2026-05-20 remaining-agents sketch (PR #52).** One short page per agent. Citations to PRD §7 / build-roadmap / verification records — terminal scope is anchored in the spec, not invented.

**Sources used (verified 2026-05-20):**

- [`docs/strategy/PRD.md`](../../strategy/PRD.md) §7.1–§7.7 — capability spec, lines 617–2050
- [`docs/superpowers/plans/2026-05-08-build-roadmap.md`](../plans/2026-05-08-build-roadmap.md) — initial-build track + "What's NOT in Phase 1" (lines 199–230)
- [`docs/_meta/system-readiness-2026-05-16-post-a1.md`](../../_meta/system-readiness-2026-05-16-post-a1.md) §14 — A.1 v0.2/v0.3/v0.4/v0.5 expansion
- [`docs/_meta/decisions/ADR-010-version-extension-template.md`](../../_meta/decisions/ADR-010-version-extension-template.md) — within-agent extension shape
- [`docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md`](2026-05-20-remaining-agents-sketch.md) — the 7 unbuilt agents' v0.1 sketches
- Per-package READMEs' "Out of scope (v0.1)" sections
- [`docs/_meta/system-readiness-2026-05-19.md`](../../_meta/system-readiness-2026-05-19.md) §5 — "What's not yet shipped"

**Conventions.** Where the PRD §7 spec is explicit, the terminal version is anchored verbatim. Where the PRD is silent (D.12 Curiosity, D.13 Synthesis, Supervisor) the terminal version is marked **speculative** — those agents will need a per-agent ADR before terminal scope is decided. Substrate-debt gates are named verbatim where they exist (SET LOCAL `$1`, cross-run AFFECTS-dedup, KG-loop §13.3 retro-point).

**Agent-ID-namespace overlap.** The 2026-05-20 sketch flags that `multi-cloud-posture/` self-claims D.5 and `k8s-posture/` self-claims D.6, while the operator's enumeration uses D.5 = Data Security and D.6 = Compliance. **This roadmap follows operator IDs for the 7 unbuilt agents** and refers to the existing packages by package name (multi-cloud-posture, k8s-posture). The renumbering decision is parked per sketch §0; not in scope here.

---

# Part A — 10 shipped agents

## §1. F.3 Cloud Posture (`packages/agents/cloud-posture/`)

**Terminal scope (PRD §7.1.1, lines 623–734).** AWS CSPM — 1,200+ patterns across 100+ services; storage / compute / database / identity / logging / networking / container / app / encryption categories. _Multi-cloud CSPM (Azure / GCP / OCI) is handled by the separate `multi-cloud-posture/` package (see §7), not by F.3._

| Version                      | Status                | What it adds                                                                                                                                                 |
| ---------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **v0.1**                     | ✅ shipped 2026-05-10 | Prowler offline-mode + boto3 IAM enrichment; OCSF v1.3 Compliance Finding `class_uid 2003`; deterministic (no LLM in loop); LocalStack integration tests     |
| **v0.1.5** (KG-loop closure) | ✅ shipped 2026-05-18 | SemanticStore write-path via `kg_writer.py` (was neo4j); entity dedup within-run; PR #33–#40                                                                 |
| **v0.2** (next)              | ⬜ unstarted          | Live boto3 SDK calls (replace LocalStack-only); AWS account inventory autodiscovery                                                                          |
| **v0.3+**                    | ⬜ unstarted          | Per build-roadmap line 209: pattern-library expansion to 1200+ patterns (currently Prowler base ~700); cross-account scanning; AWS-Organizations integration |
| **Terminal v1.0**            | per PRD               | All AWS services + cross-account / Organizations / Control Tower; live KG-loop with cross-run dedup                                                          |

**Cross-agent dependencies.** Findings consumed by D.6 Compliance (v0.1+), D.7 Investigation (v0.1+), A.1 Remediation v0.3+ (AWS Custodian artifacts). Substrate consumer of F.6 Audit + F.5 SemanticStore.

**Substrate/debt gates.**

- v0.2 live-mode blocks on no debt (boto3 stable).
- Cross-run AFFECTS-edge dedup ([KG-loop §13.1](../../_meta/kg-loop-closure-verification-2026-05-18.md#13-1)) gates terminal: at scale, within-run dedup accumulates dup edges across runs.
- Multi-tenant production blocks on SET LOCAL `$1` tenant-RLS fix ([F.5 LTREE plan-closer §11.1](../../_meta/f5-ltree-substrate-fix-verification-2026-05-19.md#11-1)).

---

## §2. D.1 Vulnerability (`packages/agents/vulnerability/`)

**Terminal scope (PRD §7.1.5, lines 996–1076).** Container images + VMs + serverless + dependencies + IaC; prioritization via CVSS / EPSS / KEV / public exploits; SCA continuous monitoring.

| Version           | Status                | What it adds                                                                               |
| ----------------- | --------------------- | ------------------------------------------------------------------------------------------ |
| **v0.1**          | ✅ shipped 2026-05-11 | Trivy primary + Grype backup + Syft SBOM; OSV-Scanner; EPSS + KEV enrichment               |
| **v0.2** (next)   | ⬜ unstarted          | Live registry scanning (currently offline JSON); image-pull policy enforcement integration |
| **v0.3+**         | ⬜ unstarted          | Malicious-package supply-chain detection (deferred Phase 2 per build-roadmap line 209)     |
| **Terminal v1.0** | per PRD               | Continuous SCA + image registry + IaC + serverless + active-exploitation context via D.8   |

**Cross-agent dependencies.** Feeds A.1 Remediation v0.4+ (vulnerability remediation per system-readiness §14); feeds D.8 Threat Intel correlation; consumes D.8 KEV/exploit feeds (when D.8 ships).

**Substrate/debt gates.**

- v0.3 malicious-package detection waits on Phase 2 (per build-roadmap §"What's NOT in Phase 1").
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §3. D.2 Identity (`packages/agents/identity/`)

**Terminal scope (PRD §7.1.3, lines 836–913).** CIEM — AWS IAM / Azure RBAC / GCP IAM full coverage; effective-permission calculation; privilege-escalation paths; over-privileged detection; anomalous-access detection.

| Version           | Status                | What it adds                                                                                                   |
| ----------------- | --------------------- | -------------------------------------------------------------------------------------------------------------- |
| **v0.1**          | ✅ shipped 2026-05-11 | AWS IAM Access Analyzer + PMapper privilege-escalation; 90-day unused-permission; cross-account trust analysis |
| **v0.2** (next)   | ⬜ unstarted          | Azure AD / Entra sync (Phase 2 per build-roadmap line 201)                                                     |
| **v0.3+**         | ⬜ unstarted          | GCP IAM full coverage; custom federation chain forensics (SAML / OIDC) — Phase 3 per build-roadmap             |
| **Terminal v1.0** | per PRD               | All three clouds + federation forensics + anomalous-access ML detection                                        |

**Cross-agent dependencies.** Feeds D.7 Investigation identity-attack-chain pivots; feeds A.1 Remediation v0.5+ (least-privilege policy drafting per system-readiness §14); correlates with D.3 Runtime Threat for lateral-movement.

**Substrate/debt gates.**

- v0.2 Azure AD blocks on Azure-SDK substrate (no debt named yet; spec-level).
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §4. D.3 Runtime Threat (`packages/agents/runtime-threat/`)

**Terminal scope (PRD §7.1.2, lines 736–834).** CWPP — Falco eBPF; process / container / network / file / K8s / OS / cloud-control-plane behaviors; max 2% CPU overhead; MITRE ATT&CK mapping.

| Version           | Status                | What it adds                                                                |
| ----------------- | --------------------- | --------------------------------------------------------------------------- |
| **v0.1**          | ✅ shipped 2026-05-11 | Falco eBPF primary + Tracee backup + OSQuery + Wazuh FIM; Linux only        |
| **v0.2** (next)   | ⬜ unstarted          | Windows CWPP (Phase 2 per build-roadmap line 201)                           |
| **v0.3+**         | ⬜ unstarted          | Autonomous-kill action (handed to A.1 Tier-1; D.3 itself stays detect-only) |
| **Terminal v1.0** | per PRD               | Linux + Windows + macOS endpoints + full ATT&CK coverage                    |

**Cross-agent dependencies.** Feeds D.7 Investigation timeline reconstruction; feeds A.1 Remediation v0.4+ (container-escape responses); correlates D.2 Identity for lateral-movement.

**Substrate/debt gates.**

- v0.2 Windows blocks on a Windows-eBPF substrate decision (no existing debt — new architectural choice for Phase 2).
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §5. F.6 Audit (`packages/agents/audit/`)

**Terminal scope (PRD §7.7.5, lines 1942–1950+).** Hash-chained immutable audit per agent invocation; 7-year retention; tamper detection; tenant isolation enforced.

| Version           | Status                | What it adds                                                                                                                       |
| ----------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1**          | ✅ shipped 2026-05-12 | OCSF v1.3 `class_uid 6003` (plan-corrected from 2004); SHA-256 hash-chain; 11-action remediation vocabulary; F.1 charter embedment |
| **v0.2** (next)   | ⬜ unstarted          | Cross-tenant query-attempt alerting (Phase 2; alerting substrate not in Phase 1c)                                                  |
| **v0.3+**         | ⬜ unstarted          | Quarterly tenant-isolation testing harness; immutability proof via external timestamping                                           |
| **Terminal v1.0** | per PRD               | 7-year retention + quarterly attest + tamper-proof external-anchoring                                                              |

**Cross-agent dependencies.** Consumed by every shipped agent (10/10). Feeds F.5 Memory timeline reconstruction. **Cross-agent dependency convergence point** — every agent writes here.

**Substrate/debt gates.**

- v0.2 alerting blocks on a fabric-alert substrate (could ride F.7 — new ADR-004 subject).
- File-backed today; SemanticStore migration is a future plan (not yet sketched).

---

## §6. D.4 Network Threat (`packages/agents/network-threat/`)

**Terminal scope (PRD §7.1.8, lines 1208–1284).** IDS — reconnaissance / lateral-movement / C2 / exfiltration / DDoS / cloud-specific; VPC flows + DNS + Suricata + DGA classifier.

| Version           | Status                | What it adds                                                                               |
| ----------------- | --------------------- | ------------------------------------------------------------------------------------------ |
| **v0.1**          | ✅ shipped 2026-05-13 | Suricata + Zeek; DGA behavioral classifier; VPC Flow Logs parser; static threat-intel      |
| **v0.2** (next)   | ⬜ unstarted          | Live `ec2.describe_flow_logs` + S3→Athena (deferred Phase 1c per network-threat README)    |
| **v0.3+**         | ⬜ unstarted          | Tor-network detection (Phase 2 per PRD); cross-window beacon baselines (needs TimescaleDB) |
| **Terminal v1.0** | per PRD               | Live multi-cloud flow ingest + ML DGA model + Tor enumeration + cross-window baselines     |

**Cross-agent dependencies.** Feeds D.7 Investigation lateral-movement timelines; consumes D.8 Threat Intel (when D.8 ships) for IOC enrichment; feeds A.1 v0.3+ (WAF blocking artifacts).

**Substrate/debt gates.**

- v0.3 cross-window baselines block on a TimescaleDB substrate addition (new; not yet sketched).
- ML DGA model deferred Phase 1c — out-of-scope for the deterministic v0.1.

---

## §7. Multi-Cloud Posture (`packages/agents/multi-cloud-posture/`, self-claims D.5)

**Terminal scope (PRD §7.1.1 extended, lines 631–632).** Azure 1,000+ patterns + GCP 800+ patterns; OCSF identical wire shape to F.3 (`class_uid 2003`). _ID overlap with operator's D.5 = Data Security flagged in [sketch §0](2026-05-20-remaining-agents-sketch.md#important-note-up-front)._

| Version           | Status                | What it adds                                                                                   |
| ----------------- | --------------------- | ---------------------------------------------------------------------------------------------- |
| **v0.1**          | ✅ shipped 2026-05-13 | Prowler multi-cloud + Defender for Cloud + GCP SCC + Activity Log + IAM bindings; offline-mode |
| **v0.2** (next)   | ⬜ unstarted          | Live `azure-mgmt-security` + `google-cloud-securitycenter` SDK calls                           |
| **v0.3+**         | ⬜ unstarted          | OCI coverage (Phase 2 per build-roadmap line 201); Alibaba Cloud (Phase 3+)                    |
| **Terminal v1.0** | per PRD               | All four major clouds (AWS+Azure+GCP+OCI) + per-cloud-specific framework mappings              |

**Cross-agent dependencies.** Findings consumed by D.6 Compliance for multi-cloud frameworks; D.7 Investigation cross-cloud attack-path; A.1 Remediation v0.3+ (multi-cloud Custodian).

**Substrate/debt gates.**

- v0.2 live SDK blocks on per-cloud credential management — F.4 tenant secret-store extension; new plan not yet scoped.
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §8. K8s Posture (`packages/agents/k8s-posture/`, self-claims D.6)

**Terminal scope (PRD §7.1.1 K8s line 633).** 600+ K8s patterns; CIS Kubernetes Benchmark + Polaris + 10-rule manifest analyzer. _ID overlap with operator's D.6 = Compliance flagged in [sketch §0](2026-05-20-remaining-agents-sketch.md#important-note-up-front)._

| Version           | Status                | What it adds                                                                                       |
| ----------------- | --------------------- | -------------------------------------------------------------------------------------------------- |
| **v0.1**          | ✅ shipped 2026-05-13 | Offline manifest-file analysis; 10-rule analyzer; OCSF 2003                                        |
| **v0.2**          | ✅ shipped 2026-05-16 | Live `kubectl --kubeconfig` mode                                                                   |
| **v0.3**          | ✅ shipped 2026-05-16 | In-cluster Pod ServiceAccount-token mode; 3-way XOR `--manifest-dir / --kubeconfig / --in-cluster` |
| **v0.4** (next)   | ⬜ unstarted          | Pattern-library expansion (10 → 100+ rules); CIS Kubernetes Benchmark full implementation          |
| **v0.5+**         | ⬜ unstarted          | Mutating-webhook auto-deployment (deferred Phase 2); admission-controller integration              |
| **Terminal v1.0** | per PRD               | Full 600+ K8s patterns + CIS Benchmark + admission-webhook deploy                                  |

**Cross-agent dependencies.** Feeds A.1 Remediation 5 K8s action classes today (v0.1+3 in v0.2 per system-readiness §14); D.7 Investigation workload pivots; F.6 Audit per-namespace isolation.

**Substrate/debt gates.**

- Within-run dedup only — cross-run AFFECTS-edge dedup is known debt (KG-loop §13.1); blocks cross-run consistent operator-facing views.
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §9. D.7 Investigation (`packages/agents/investigation/`)

**Terminal scope (PRD §7.3, lines 1415–1512).** Forensic orchestrator — automated triage / timeline reconstruction / RCA / IOC pivoting / MITRE ATT&CK mapping / cross-domain correlation / forensic snapshot.

| Version             | Status                | What it adds                                                                                                                                                                                  |
| ------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1**            | ✅ shipped 2026-05-13 | 6-stage Orchestrator-Workers pipeline; 4 sub-investigations (timeline / IOC / asset_enum / attribution); OCSF v1.3 Incident Finding `class_uid 2005`; load-bearing LLM (hypothesis synthesis) |
| **v0.2** (F.7 v0.2) | ✅ shipped 2026-05-18 | Lifecycle events on `events.>` fabric bus; first agent on F.7 substrate                                                                                                                       |
| **v0.3** (next)     | ⬜ unstarted          | Threat-intel API integration (PRD §7.3.4 IOC pivoting); requires D.8 to ship first                                                                                                            |
| **v0.4+**           | ⬜ unstarted          | Real-time triage (Phase 1c per system-readiness); forensic snapshot infra (Phase 2)                                                                                                           |
| **Terminal v1.0**   | per PRD               | Real-time triage + automatic IOC pivot + forensic snapshot + MITRE ATT&CK full mapping                                                                                                        |

**Cross-agent dependencies.** Reads ALL sibling-agent findings; produces `incident_report.json` for D.13 Synthesis (when D.13 ships); feeds A.1 Remediation containment plans; depends on F.5 Memory `memory_neighbors_walk` + F.6 Audit.

**Substrate/debt gates.**

- v0.3 threat-intel integration blocks on D.8 Threat Intel shipping (cross-agent dependency).
- Sub-agent orchestrator hoist to `charter.subagent` (ADR-007 v1.4) — deferred at 1 consumer; hoists at 3rd duplicate (per ADR-007).
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §10. A.1 Remediation (`packages/agents/remediation/`)

**Terminal scope (PRD §7.4, lines 1513–1651).** Three-tier authority — Tier 1 autonomous / Tier 2 approval-gated / Tier 3 recommend-only; Tier 1 initial 8 action classes (rotate-keys / disable-public-ACLs / quarantine-workloads / block-bad-IPs / disable-SAs / revoke-sessions / patch-non-prod / remove-stale-IAM).

| Version                                           | Status                | What it adds                                                                                                                                                                     |
| ------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1**                                          | ✅ shipped 2026-05-16 | Three modes (`--recommend` / `--dry_run` / `--execute`) collapsed from 3 sequential plans; 9 safety primitives; 7-stage pipeline; first OCSF 2007 producer; 5 K8s action classes |
| **v0.1.1**                                        | ✅ shipped 2026-05-17 | Earned-autonomy promotion pipeline (Stage 1→2→3→4); per-action-class graduation tracking                                                                                         |
| **v0.1.2**                                        | ✅ shipped 2026-05-17 | `remediation promotion` CLI; promotion-eval cases                                                                                                                                |
| **v0.2** (next, sketched in system-readiness §14) | ⬜ unstarted          | +3 K8s action classes: `host-network-removal` / `auto-mount-sa-token` / `privileged-container-removal`; effort ~3 wks                                                            |
| **v0.3** (sketched)                               | ⬜ unstarted          | AWS remediation: F.3 findings → Cloud Custodian artifacts; effort ~4 wks                                                                                                         |
| **v0.4** (sketched)                               | ⬜ unstarted          | Azure + GCP posture remediation                                                                                                                                                  |
| **v0.5** (sketched)                               | ⬜ unstarted          | Vulnerability remediation (consumes D.1 findings); Identity remediation (consumes D.2)                                                                                           |
| **v0.6+** (sketched)                              | ⬜ unstarted          | S.3 ChatOps approval integration (Tier-2 surface); off critical path today                                                                                                       |
| **Terminal v1.0**                                 | per PRD               | 8 Tier-1 classes + 25+ Tier-2 classes + multi-cloud + Cloud Custodian + Terraform diff + IAM-least-privilege drafting + multi-channel approval workflows                         |

**Cross-agent dependencies.** Consumes findings from F.3 / D.1 / D.2 / D.3 / D.4 / multi-cloud-posture / k8s-posture; produces OCSF 2007 for D.7 + A.4 Meta-Harness + F.6 Audit. **A.1 v0.5 Identity remediation depends on D.2 v0.2+ (Azure / GCP) shipping first.**

**Substrate/debt gates.**

- A.1 Stage 3 / Stage 4 (`--execute`) customer enablement blocks on customer-side prerequisites ([a1-safety-verification-2026-05-16 §6](../../_meta/a1-safety-verification-2026-05-16.md#6)).
- Multi-tenant remediation blocks on SET LOCAL `$1` fix.
- Tier-2 ChatOps (v0.6+) blocks on S.3 plan (separate Surface-track plan, not yet scoped).

---

# Part B — 7 unbuilt agents

## §11. D.5 Data Security / DSPM (operator ID; conflicts with multi-cloud-posture's self-claim)

**Terminal scope (PRD §7.1.4, lines 915–994).** Discover + classify + protect sensitive data across S3 / Blob / Cloud Storage / RDS / Snowflake / BigQuery / EFS / Kinesis / Bedrock / Vertex; PII / PHI / PCI / financial / auth / IP detection; public-access / over-privileged / residency-violation / toxic-combination detection. **Privacy contract: never log values; classifications-only; sample-based scanning.**

| Version                                                                                                                   | Status         | What it adds                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1** (next, sketched in [remaining-agents-sketch §1](2026-05-20-remaining-agents-sketch.md#1-data-security-d5--dspm)) | ⬜ unstarted   | AWS S3 only, offline-mode (boto3 inventory snapshots); regex/Luhn classifier agent-local; 4 detectors (public bucket / unencrypted / sensitive-in-untrusted / oversharing-IAM); F.3 finding cross-correlation; single-tenant |
| **v0.2**                                                                                                                  | ⬜ unstarted   | Live boto3 S3 SDK calls; classifier expansion (date-of-birth, addresses, healthcare IDs); Macie cross-validation                                                                                                             |
| **v0.3**                                                                                                                  | ⬜ unstarted   | RDS + DynamoDB + RDS-snapshot scanning (relational + key-value databases); AWS-native classifier API                                                                                                                         |
| **v0.4**                                                                                                                  | ⬜ unstarted   | Azure Blob + Azure SQL; GCP Cloud Storage + BigQuery; multi-cloud DSPM                                                                                                                                                       |
| **v0.5+**                                                                                                                 | ⬜ unstarted   | Snowflake + Bedrock / Vertex training-data forensics; Presidio custom classifier engine; toxic-combination detection cross-correlating D.6 / F.3                                                                             |
| **Terminal v1.0**                                                                                                         | per PRD §7.1.4 | All storage substrates (S3+Blob+GCS+RDS+Snowflake+BigQuery+EFS+Kinesis+Bedrock+Vertex) + PII/PHI/PCI classification + residency-violation + toxic-combination + privacy contract enforced                                    |

**Cross-agent dependencies.** Feeds D.6 Compliance for GDPR/CCPA/HIPAA framework mapping (v0.1 cross-correlation; v0.4+ deep integration); D.7 Investigation pivots on data-exfiltration findings; D.8 Threat Intel correlates data-breach campaigns. **No dep on the other 6 unbuilt agents in v0.1** (per sketch §1).

**Substrate/debt gates.**

- v0.1 single-tenant — SET LOCAL `$1` fix NOT a blocker (sketch §1 confirmed).
- v0.4 multi-cloud blocks on multi-cloud-posture's v0.2 live-SDK pattern (re-use credentials substrate).
- v0.5+ Bedrock / Vertex training-data forensics blocks on a Phase 2 AI-Security substrate (per PRD §7.1.9 cross-reference) — not yet scoped.
- Custom classifier engine v0.5+ may hoist to `charter.data_classification` if D.6 Compliance or D.12 Curiosity end up needing it (per sketch §1 + ADR-007 3rd-consumer hoist rule).

---

## §12. D.6 Compliance (operator ID; conflicts with k8s-posture's self-claim)

**Terminal scope (PRD §7.5, lines 1653–1783).** Continuous monitoring of 100+ frameworks (CIS / NIST / ISO 27001 / SOC 2 / PCI / HIPAA / HITRUST / FedRAMP / GDPR / CCPA); audit-ready evidence collection; control-by-control framework mapping; compliance-drift detection; auditor access + reporting.

| Version                                                                                                          | Status       | What it adds                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **v0.1** (next, sketched in [remaining-agents-sketch §2](2026-05-20-remaining-agents-sketch.md#2-compliance-d6)) | ⬜ unstarted | Reads existing detect findings via F.6 audit chain; bundled framework definitions (YAML) — CIS-AWS + SOC 2 + HIPAA basic; OCSF 2003 with `compliance.control` mapping; single-tenant |
| **v0.2**                                                                                                         | ⬜ unstarted | +PCI-DSS + GDPR + CCPA control mappings; depends on D.5 Data Security v0.1 having shipped (data-security framework controls — GDPR Art.30 etc. — need DSPM findings)                 |
| **v0.3**                                                                                                         | ⬜ unstarted | ISO 27001 + NIST 800-53 + HITRUST control mappings; healthcare content pack 80% complete                                                                                             |
| **v0.4+**                                                                                                        | ⬜ unstarted | Compliance-drift detection (delta from last quarter); auditor-portal export (PDF / CSV / evidence-zip); audit-ready evidence collection per control                                  |
| **v0.5+**                                                                                                        | ⬜ unstarted | FedRAMP Moderate + StateRAMP (Phase 2-3 per PRD §12.1 lines 2159–2182)                                                                                                               |
| **Terminal v1.0**                                                                                                | per PRD      | All 110+ frameworks + SOC 2 Type II deep + auditor portal + drift detection + Phase 1 vertical packs (tech, healthcare)                                                              |

**Cross-agent dependencies.** Consumes findings from ALL detect agents (F.3 + D.1 + D.2 + D.3 + D.4 + multi-cloud-posture + k8s-posture + D.5 when shipped + D.8 when shipped); consumes A.1 Remediation evidence; consumes D.7 Investigation incident reports for control-violation mapping.

**Substrate/debt gates.**

- v0.2 GDPR/CCPA blocks on D.5 Data Security v0.1 shipping (data-controls need DSPM findings).
- v0.5 FedRAMP blocks on Phase 2 compliance-cert workstream (per PRD §12.1).
- Multi-tenant production blocks on SET LOCAL `$1` fix — Compliance's cross-tenant aggregation is inherently SET-LOCAL-sensitive (per sketch §2).
- v0.4 drift detection blocks on temporal substrate (TimescaleDB candidate) — not yet scoped.

---

## §13. D.8 Threat Intel

**Terminal scope (PRD §7.6, lines 1785–1892).** Continuous external feed ingestion (MITRE / CISA / cloud-provider bulletins / OTX / abuse.ch / VirusTotal / FS-ISAC + H-ISAC for verticals); customer-specific threat correlation; active-campaign tracking; industry-specific briefings; vulnerability-exploitation prioritization.

| Version                                                                                                            | Status       | What it adds                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **v0.1** (next, sketched in [remaining-agents-sketch §3](2026-05-20-remaining-agents-sketch.md#3-threat-intel-d8)) | ⬜ unstarted | Public CVE/KEV feeds (NVD JSON + CISA KEV); IOC enrichment on existing D.1/D.4/D.3 findings; basic MITRE ATT&CK technique mapping; SemanticStore IOC/TTP/CVE entities; single-tenant |
| **v0.2**                                                                                                           | ⬜ unstarted | MISP + STIX/TAXII server integration; abuse.ch + VirusTotal IOC feeds                                                                                                                |
| **v0.3**                                                                                                           | ⬜ unstarted | Active-campaign tracking (PRD §7.6.3); customer-specific correlation engine                                                                                                          |
| **v0.4**                                                                                                           | ⬜ unstarted | Vertical-specific feeds (FS-ISAC for finance, H-ISAC for healthcare — Phase 2 per build-roadmap)                                                                                     |
| **v0.5+**                                                                                                          | ⬜ unstarted | Predictive-exploitation-risk modeling (Phase 3 per PRD); custom threat-actor attribution                                                                                             |
| **Terminal v1.0**                                                                                                  | per PRD §7.6 | All public + vertical-private feeds + active-campaign + predictive + custom attribution + vulnerability-prioritization                                                               |

**Cross-agent dependencies.** Feeds D.1 Vulnerability (KEV/active-exploitation context); D.2 Identity (federation-threat); D.4 Network Threat (DGA/C2 IOCs — uplift bundled static intel to live); D.7 Investigation v0.3+ (attribution); A.1 Remediation (threat-prioritization context). **No dep on the other 6 unbuilt agents in v0.1** (per sketch §3).

**Substrate/debt gates.**

- v0.1 single-tenant — SET LOCAL `$1` fix NOT a blocker (sketch §3 confirmed).
- v0.5 predictive modeling defers Phase 3 (out of Phase 1 GA scope).
- D.4 Network Threat live-IOC consumption (uplift from bundled static intel) is a D.4 v0.2+ change driven by D.8 v0.1 shipping — cross-agent coupling, but doesn't block D.8 itself.

---

## §14. D.12 Curiosity

**Terminal scope** ⚠️ **speculative** — no canonical PRD §7 section. Build-roadmap line 81: "**D.12** | Curiosity Agent (#11) — background 'wonder' agent with idle scheduler | Custom; uses all read-only tools from other agents | AI/Agent Eng | 3 wks". VISION.md §4.2 hints at "proactive exploration." Will require a per-agent ADR before terminal scope is decided.

| Version                                                                                                    | Status       | What it adds                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **v0.1** (sketched in [remaining-agents-sketch §4](2026-05-20-remaining-agents-sketch.md#4-curiosity-d12)) | ⬜ unstarted | Hypothesis generation over coverage gaps (regions / asset-types with finding-counts << inventory); reads D.1–D.8 + D.13 findings; writes `hypothesis` entities to SemanticStore; possible new F.7 subject (`claims.>`) — substrate decision deferred to plan |
| **v0.2**                                                                                                   | ⬜ unstarted | Hypothesis-validation loop: closes the hypothesis when subsequent finding-fired evidence confirms or refutes                                                                                                                                                 |
| **v0.3+**                                                                                                  | ⬜ unstarted | Cross-customer-pattern distillation (vendor-curated, anonymised; Phase 2 per build-roadmap line 209)                                                                                                                                                         |
| **Terminal v1.0**                                                                                          | speculative  | Continuous idle-loop hypothesis generation + validation + cross-customer pattern feed + per-vertical Curiosity tuning                                                                                                                                        |

**Cross-agent dependencies.** Consumes findings from D.1–D.8 + D.13 Synthesis claims; feeds D.5 Data Security + D.6 Compliance + D.7 Investigation + D.8 Threat Intel as probe directives. **Most-dependent of the 7 unbuilt agents** — must come late in sequence (per sketch §8).

**Substrate/debt gates.**

- v0.1 may introduce new F.7 subject (`claims.>`) — substrate decision; if so, F.7 v0.3+ extension plan needed.
- New OCSF class for exploratory claims is a schema-layer decision (not substrate).
- v0.3 cross-customer pattern distillation defers Phase 2.
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §15. D.13 Synthesis

**Terminal scope** ⚠️ **partially speculative** — PRD §7.7.1 conversational interface (lines 1896–1910) implies customer-facing narrative, but no §7 dedicated section. Build-roadmap line 82: "**D.13** | Synthesis Agent (#12) — cross-agent reasoning, customer-facing narrative | Claude Opus 4.5 | 3 wks". VISION.md §4.2 names Synthesis explicitly. Will need per-agent ADR for terminal scope.

| Version                                                                                                    | Status       | What it adds                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1** (sketched in [remaining-agents-sketch §5](2026-05-20-remaining-agents-sketch.md#5-synthesis-d13)) | ⬜ unstarted | LLM-driven cross-source synthesis; reads D.7 Investigation conclusions + D.6 Compliance reports + sibling-agent findings; markdown / HTML report output; uses `charter.llm.LLMProvider` (no new substrate); fabric emit via F.7 (existing client) |
| **v0.2**                                                                                                   | ⬜ unstarted | D.12 Curiosity hypothesis narration ("areas we're proactively watching"); chat-surface integration (Surface-track S.2 console — separate plan)                                                                                                    |
| **v0.3+**                                                                                                  | ⬜ unstarted | Per-vertical narrative tuning (healthcare → HIPAA framing; finance → SOC 2 framing); per-persona output shapes (CISO summary / analyst deep-dive / auditor evidence-pack)                                                                         |
| **Terminal v1.0**                                                                                          | per VISION   | Real-time conversational synthesis across all 17 agents + per-vertical-narrative + per-persona-output + integrates with console chat surface                                                                                                      |

**Cross-agent dependencies.** Consumes D.7 Investigation (existing), D.6 Compliance (when shipped), D.8 Threat Intel (when shipped), D.12 Curiosity (v0.2+). **No dep on D.5 Data Security or A.1 Remediation directly** (their findings reach Synthesis via D.7).

**Substrate/debt gates.**

- v0.1 no substrate work (per sketch §5).
- v0.2 console chat integration blocks on Surface-track S.2 plan (not yet scoped).
- Multi-tenant production blocks on SET LOCAL `$1` fix.

---

## §16. A.4 Meta-Harness

**Terminal scope (PRD §7.7.6, lines 1960–1972).** Reads raw execution traces; proposes NLAH optimizations; eval-gates; signs; deploys via canary; customer-specific tuning automatic; cross-customer pattern distillation vendor-curated; all optimization auditable + transparent.

| Version                                                                                                      | Status         | What it adds                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------ | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1** (sketched in [remaining-agents-sketch §6](2026-05-20-remaining-agents-sketch.md#6-meta-harness-a4)) | ⬜ unstarted   | Batch eval across all 16 prior agents; per-agent scorecard with delta-over-time; agent-introspection primitives (NLAH-dir parsing); A/B comparison runner. **Substrate-heaviest of the 7** (per sketch §6) |
| **v0.2**                                                                                                     | ⬜ unstarted   | NLAH-change proposal generation (markdown reports to operator)                                                                                                                                             |
| **v0.3**                                                                                                     | ⬜ unstarted   | Automatic NLAH-patch generation (still gated by human review per ADR-011)                                                                                                                                  |
| **v0.4+**                                                                                                    | ⬜ unstarted   | Auto-deploy of major NLAH rewrites without human review — deferred Phase 2-3 per build-roadmap line 209                                                                                                    |
| **v0.5+**                                                                                                    | ⬜ unstarted   | Cross-customer pattern distillation (Phase 2 per PRD); per-customer eval persistence                                                                                                                       |
| **Terminal v1.0**                                                                                            | per PRD §7.7.6 | Auto-NLAH tuning + canary deploy + cross-customer pattern feed + transparent + auditable                                                                                                                   |

**Cross-agent dependencies.** Reads eval suites + NLAH directories of all 16 prior agents (must come after the 6 prior unbuilt have shipped per sketch §8). Depends on F.2 Eval Framework; depends on F.6 Audit for proposal-integrity chain. **2nd-to-last in sequence** (per sketch §8).

**Substrate/debt gates.**

- v0.1 requires new substrate per sketch §6: agent-introspection primitives + cross-agent batch eval extension + A/B comparison runner. May warrant own substrate-extension ADR.
- v0.4 auto-deploy defers Phase 2-3.
- v0.5 cross-customer defers Phase 2.
- Per sketch §6, **least affected by SET LOCAL** (operates on file-based eval state, not SemanticStore primarily).

---

## §17. Supervisor (#0)

**Terminal scope** ⚠️ **substantially speculative** — PRD §18 Glossary line 2384: "**Supervisor:** The lightweight routing agent that delegates work to specialists. Does not perform detection or remediation directly." VISION §4.2 lines 188–195 names it. Glossary line 2378: "**Heartbeat:** The 60-second cycle on which the supervisor agent triggers periodic processing." No PRD §7 dedicated section. Will need per-agent ADR — sketch §6 calls Supervisor's full plan "more like a substrate plan than an agent plan."

| Version                                                                                                         | Status       | What it adds                                                                                                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v0.1** (sketched in [remaining-agents-sketch §7](2026-05-20-remaining-agents-sketch.md#7-supervisor-0--last)) | ⬜ unstarted | Agent registry (`charter.agent_registry` — new substrate); ExecutionContract dispatch machinery; basic 60s heartbeat loop; reads F.7 events for in-flight work tracking; **substrate-heaviest agent of the 7** |
| **v0.2**                                                                                                        | ⬜ unstarted | Escalation handler — acts on charter contracts' `escalation_rules` field; routes Tier-2 / Tier-3 approvals to S.3 ChatOps (when S.3 ships)                                                                     |
| **v0.3**                                                                                                        | ⬜ unstarted | Routing decisions informed by A.4 Meta-Harness scorecards (which agent to use when multiple can handle a task)                                                                                                 |
| **v0.4+**                                                                                                       | ⬜ unstarted | Cross-agent orchestration meta-events (possible new F.7 subject `orchestration.>` — substrate-level F.7 stream extension)                                                                                      |
| **Terminal v1.0**                                                                                               | per VISION   | Real-time agent orchestration across all 17 specialists; full escalation handling; routing-by-scorecard; full F.7 fabric integration                                                                           |

**Cross-agent dependencies.** Orchestrates ALL 17 prior agents (existing 10 + 6 new). Depends on A.4 Meta-Harness for routing decisions. **Last in sequence by operator directive AND by structural necessity** (per sketch §8).

**Substrate/debt gates.**

- v0.1 requires new substrate: `charter.agent_registry` + contract-dispatch machinery. Probably its own ADR (per sketch §7).
- v0.2 Tier-2/3 escalation blocks on S.3 ChatOps plan shipping.
- v0.4 `orchestration.>` subject — new ADR-004 extension; may slot before or after Supervisor v0.1 depending on ordering.
- Multi-tenant production blocks on SET LOCAL `$1` fix (Supervisor is per-tenant by design — DEFINITELY uses `MemoryService.session(tenant_id=...)`).
- **By Supervisor's build time, the SET LOCAL fix may already have landed** (sketch §7).

---

# Part C — cross-agent version-dependency matrix

The non-trivial cross-agent gates that gate **specific versions**, not v0.1s:

| Gates this version                      | Of this agent      | On this version of      | This other agent                                   |
| --------------------------------------- | ------------------ | ----------------------- | -------------------------------------------------- |
| v0.3 (threat-intel integration)         | D.7 Investigation  | v0.1 ships              | D.8 Threat Intel                                   |
| v0.2 (data-security framework controls) | D.6 Compliance     | v0.1 ships              | D.5 Data Security                                  |
| v0.2 (live IOC consumption)             | D.4 Network Threat | v0.1 ships              | D.8 Threat Intel                                   |
| v0.5 (Identity remediation)             | A.1 Remediation    | v0.2+ (Azure/GCP) ships | D.2 Identity                                       |
| v0.4 (vulnerability remediation)        | A.1 Remediation    | v0.1 already shipped    | D.1 Vulnerability ✓                                |
| v0.2 (Curiosity hypothesis narration)   | D.13 Synthesis     | v0.1 ships              | D.12 Curiosity                                     |
| v0.1 (agent introspection)              | A.4 Meta-Harness   | v0.1 of all 6 unbuilt   | D.5 / D.6 / D.8 / D.12 / D.13 + Supervisor not yet |
| v0.3 (scorecard routing)                | Supervisor         | v0.1 ships              | A.4 Meta-Harness                                   |
| v0.2 (ChatOps escalation)               | Supervisor         | S.3 plan ships          | (out-of-roadmap-scope)                             |

---

# Part D — substrate / carry-forward debt gates (named per-debt + which versions each blocks)

| Debt                                                          | Source                                                                                            | Blocks                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SET LOCAL `$1` tenant-RLS bug**                             | [F.5 LTREE plan-closer §11.1](../../_meta/f5-ltree-substrate-fix-verification-2026-05-19.md#11-1) | **Multi-tenant production** of every agent. v0.1 single-tenant builds are NOT blocked (sketch §8 invariant 2). Multi-tenant blocks: F.3 v0.2+, D.1 v0.2+, D.2 v0.2+, D.3 v0.2+, multi-cloud v0.2+, k8s v0.4+, D.7 v0.3+, A.1 v0.3+, D.5 v0.2+, D.6 v0.2+, D.8 v0.2+, D.12 v0.2+, D.13 v0.2+, Supervisor v0.1+ (most affected; substrate-heaviest). **Owner: future tenant-RLS substrate-fix plan.** |
| **Cross-run AFFECTS-edge dedup**                              | [KG-loop closure verification §13.1](../../_meta/kg-loop-closure-verification-2026-05-18.md#13-1) | Cross-run consistent operator-facing views in F.3 + k8s-posture + D.5 + every SemanticStore-writing agent. Within-run dedup proven. Does not block v0.1 of any agent. **Owner: future substrate-uniqueness plan.**                                                                                                                                                                                  |
| **KG-loop §13.3 retro-point**                                 | [KG-loop closure verification §13.3](../../_meta/kg-loop-closure-verification-2026-05-18.md#13-3) | Letter-vs-spirit deviation (`Base.metadata.create_all` vs `alembic upgrade head`). Newly-unblocked by F.5 LTREE fix 2026-05-20. Does not block any agent v0.1. **Owner: future cloud-posture-test-restore plan; sequencing-blocks on SET LOCAL fix.**                                                                                                                                               |
| **F.7 v0.2 NATS v2.14.0 / v2.10-alpine permanent limitation** | [F.7 v0.1 verification](../../_meta/f-7-v0-1-verification-2026-05-17.md)                          | F.7 live lane runs against brew-installed NATS only. Documented permanent limitation; not a defect. Does not block any agent.                                                                                                                                                                                                                                                                       |
| **Customer-side prerequisites for A.1 Stage 3 / Stage 4**     | [A.1 safety verification §6](../../_meta/a1-safety-verification-2026-05-16.md#6)                  | Per-customer A.1 `--execute` enablement. Stage 1 (`recommend`) + Stage 2 (`dry_run`) shippable today. **Owner: per-customer customer-success workstream.**                                                                                                                                                                                                                                          |

---

# Part E — what this doc is NOT

- **Not a full plan for any agent.** Per-agent plans still get written one at a time, executing under [ADR-011 PR-flow discipline](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md).
- **Not a code change.** No package touched.
- **Not a revision to the 2026-05-20 remaining-agents sketch (PR #52).** This doc _cites_ the sketch and _extends_ it with version-trajectory content; the sketch itself stays at v0.1-scope-only.
- **Not a commitment to specific timing per version.** Calendar compression / ordering shifts are roadmap-level decisions; this doc maps shape, not ETA.
- **Not a resolution of the agent-ID-namespace overlap.** Operator IDs used for the 7 unbuilt; flagged in [sketch §0](2026-05-20-remaining-agents-sketch.md#important-note-up-front).
- **Not a commitment to building Curiosity / Synthesis / Supervisor exactly as speculatively-sketched.** Those three need per-agent ADRs (or shared ADRs) at plan-time. The speculative terminal-scope rows above (§14 / §15 / §17) carry a ⚠️ flag.

---

# Part F — closing

Per-agent version trajectories are now mapped at sketch-depth. The next decision point is: **does each unbuilt agent's v0.1 scope sit cleanly inside its trajectory, given visibility of v0.2 / v0.3 / terminal?** That sanity check lives in a separate companion artifact (this doc is the map; the sanity-check is a one-time read-through against the map). Per operator directive 2026-05-20: **no plan started; no code; pause for review of this roadmap doc + the companion sanity-check before any D.5 plan is written.**
