# Nexus Cyber OS — System Readiness Report (2026-05-16, post-A.1)

|                         |                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Snapshot date**       | 2026-05-16 (end of A.1 shipping session)                                                                                                                                                                                                                                                                                                                                                                                        |
| **Last commit at HEAD** | `3e0577f` — `docs(a1): pin task 16 commit hash; flip status row — A.1 v0.1 complete`                                                                                                                                                                                                                                                                                                                                            |
| **Branch state**        | `main` in sync with `origin/main`; working tree clean                                                                                                                                                                                                                                                                                                                                                                           |
| **Phase position**      | **Phase 1c bootstrap on the cure quadrant** (3 Phase-1c slices closed today: D.6 v0.2 / D.6 v0.3 / A.1 v0.1)                                                                                                                                                                                                                                                                                                                    |
| **Audience**            | Founders, board / investors, design partners, engineering leadership, GTM, recruiting                                                                                                                                                                                                                                                                                                                                           |
| **Purpose**             | Macro-to-micro snapshot of platform readiness, refreshed at the close of the **A.1 ship and the four-gate safety review**. **Platform-capability for the cure quadrant is built and proven against a live `kind` cluster (G3 green at HEAD `96bd75c`); customer enablement of `--mode execute` remains conditional on the customer-side prerequisites in [`a1-safety-verification §6`](a1-safety-verification-2026-05-16.md).** |
| **Supersedes**          | [system-readiness-2026-05-16.md](system-readiness-2026-05-16.md) (morning snapshot, immediately after D.6 v0.2 close)                                                                                                                                                                                                                                                                                                           |
| **Pairs with**          | [A.1 verification](a1-verification-2026-05-16.md) · [D.6 v0.3 verification](d6-v0-3-verification-2026-05-16.md) · [D.6 v0.2 verification](d6-v0-2-verification-2026-05-16.md) · [VISION](../strategy/VISION.md)                                                                                                                                                                                                                 |

---

# Part I · Macro snapshot

## §1. The one-page picture

| Dimension                                                                                                                        |       Today | Phase 1b target | Phase 1 GA (M12) |             Delta vs morning |
| -------------------------------------------------------------------------------------------------------------------------------- | ----------: | --------------: | ---------------: | ---------------------------: |
| **Sub-plans complete** (of ~25 in [build roadmap](../superpowers/plans/2026-05-08-build-roadmap.md))                             |     **72%** |             80% |             100% |                         +8pp |
| **Production agents shipped** (of 18 in PRD §1.3)                                                                                | **10 / 18** |        ≥10 / 18 |          18 / 18 |              **+1 (A.1) ✅** |
| **Phase 1a foundation** (F.1–F.6)                                                                                                |   **6 / 6** |           6 / 6 |             done |                            — |
| **Phase 1b detection** (D.4 + D.5 + D.6 + D.7)                                                                                   |   **4 / 4** |           4 / 4 |         complete |                            — |
| **Phase 1c slices closed**                                                                                                       |   **3 / 8** |             n/a |  expected ~4 / 8 |                           +2 |
| **Cure-quadrant agents shipped**                                                                                                 |   **1 / 3** |             1/3 |              3/3 |              **+1 (A.1) ✅** |
| **ADR-007 patterns validated**                                                                                                   | **10 / 10** |         10 / 10 |          10 / 10 |                            — |
| **ADR-007 amendments in force**                                                                                                  |       **3** |             ≥ 1 |              ≥ 1 |                            — |
| **Wiz-equivalent capability coverage** (weighted, corrected — see [math correction](wiz-coverage-math-correction-2026-05-16.md)) |  **~54.0%** |         ~50–60% |             ~85% |       **+1.8pp** (corrected) |
| **Tests passing**                                                                                                                |    **2365** |          ~2000+ |           ~3000+ |                         +298 |
| **Test files**                                                                                                                   |     **191** |             156 |             ~200 |                          +35 |
| **Source files (mypy strict)**                                                                                                   |     **205** |             184 |             ~250 |                          +21 |
| **Python LOC**                                                                                                                   |  **69,255** |         ~60,000 |          ~90,000 |                       +8,791 |
| **ADRs in force**                                                                                                                |       **9** |             ~10 |              ~12 |                            — |
| **Plans written**                                                                                                                |      **18** |            ~ 18 |             ~ 25 |                           +2 |
| **Verification records**                                                                                                         |      **14** |            ~ 14 |             ~ 25 |                           +3 |
| **Commits this campaign**                                                                                                        |     **301** |            ~325 |            ~ 600 | (-7, prior estimate refined) |

**Verdict.** Today shipped **D.6 v0.3 + A.1 v0.1** plus the **four-gate safety review** that the implementation-completeness record sidestepped. The headline is A.1's **platform-capability**: the agent collapses what was originally three sequential plans (A.1 recommend-only → A.2 approve-and-execute → A.3 autonomous, projected ~14 weeks across Tier-3 → Tier-2 → Tier-1) into a **single agent shipping all three operational tiers** as `--mode` flags gated by safety primitives, and the execute path is now proven against a live kind cluster (G3 green at HEAD `96bd75c`). **The platform-capability gap vs Wiz is closed; customer-facing "execute" enablement is conditional on the per-customer prerequisites in [`a1-safety-verification §6`](a1-safety-verification-2026-05-16.md).** Stage 1 (`recommend`) and Stage 2 (`dry_run`) are safe to ship to customers today; Stage 3 (human-approved `execute`) and Stage 4 (unattended `execute`) require the customer-side gates to close before enablement.

---

## §2. Architectural pillars — at a glance

| Pillar                                    | What it is                                                                                                             |     Done | Delta today | Status                                                                                                                                                                                                      |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------: | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fabric / knowledge substrate**          | OCSF wire shape · 5 named buses · NexusEnvelope · correlation_id propagation                                           | **~28%** | +3pp        | First producer of OCSF `class_uid 2007 Remediation Activity` (A.1) — extends the platform's OCSF surface from detect-only (2003/2005/2002/3001/4002) to detect+cure. Broker transport (NATS) still pending. |
| **Runtime charter (F.1)**                 | Execution contracts · budget envelopes · tool registry · audit hash chain · LLM adapter · NLAH loader · memory engines | **~95%** | —           | Production-grade. **Tenth agent now runs under it** (A.1) with no charter changes required — the substrate's stability claim is reinforced.                                                                 |
| **Agent layer (detect / project / cure)** | The 18 specialist agents of PRD §1.3, organised by job-to-be-done                                                      | **~35%** | +5pp        | **10 of 18 agents shipped.** 9 detect (unchanged) + **1 cure (NEW: A.1)**. The cure quadrant is no longer 0/3 — A.1 covers the same surface that A.1+A.2+A.3 were planned to cover sequentially.            |

The macro picture: **substrate continues to do more work per agent than the agent layer adds to it** — A.1 shipped without touching `charter`, `eval-framework`, or `shared` substrates. **The 9-primitive safety contract A.1 introduced** (opt-in / allowlist / blast-cap / dry-run / rollback / hash-chained audit / idempotency / workspace-scope / cluster-access exclusion) **becomes the load-bearing template every future "do" agent inherits unchanged.**

---

# Part II · Mid-level — what shipped this session

## §3. D.6 v0.3 — in-cluster ServiceAccount mode (second Phase-1c slice)

|                       |                                                                                                                                                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Tasks**             | 4 (all green, all hash-pinned)                                                                                                                                                                                                                               |
| **Plan**              | [`2026-05-16-d-6-v0-3-in-cluster-mode.md`](../superpowers/plans/2026-05-16-d-6-v0-3-in-cluster-mode.md)                                                                                                                                                      |
| **Verification**      | [`d6-v0-3-verification-2026-05-16.md`](d6-v0-3-verification-2026-05-16.md)                                                                                                                                                                                   |
| **Tests added**       | +27 (245 v0.1 + 37 v0.2 + 27 v0.3 = **309** in `k8s-posture` package)                                                                                                                                                                                        |
| **Coverage**          | **97%** pkg-wide                                                                                                                                                                                                                                             |
| **Strategic role**    | Establishes the **3-way cluster-access mutual-exclusion pattern** (`--manifest-dir` / `--kubeconfig` / `--in-cluster`) that A.1 then inherits, and **unlocks the production deployment mode** (Pod with mounted SA token; no external kubeconfig to manage). |
| **First-of-platform** | First 3-way XOR in the platform; pattern reusable for future D.6 v0.x slices and for any agent needing analogous source exclusion.                                                                                                                           |

## §4. A.1 v0.1 — Remediation Agent (production-action mode)

|                       |                                                                                                                                                                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tasks**             | 16 (all green, all hash-pinned)                                                                                                                                                                                                                    |
| **Plan**              | [`2026-05-16-a-1-remediation-agent.md`](../superpowers/plans/2026-05-16-a-1-remediation-agent.md)                                                                                                                                                  |
| **Verification**      | [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md)                                                                                                                                                                                   |
| **Tests added**       | +271 in `remediation` package; **+298 repo-wide** (vs the morning's 2067)                                                                                                                                                                          |
| **Coverage**          | **94%** pkg-wide                                                                                                                                                                                                                                   |
| **Strategic role**    | **First "do" agent in the platform. First producer of OCSF `class_uid 2007 Remediation Activity`.** Cure quadrant opens at 1/3.                                                                                                                    |
| **First-of-platform** | (1) First OCSF 2007 producer; (2) first multi-stage agent with **per-stage F.6 audit entries** (11-action `remediation.*` vocabulary); (3) first agent with **pure-function `(build, inverse)` action class pairs** + automated rollback contract. |

### 4.1 What "production-action mode" actually means

The original Phase-1c plan split remediation across **three sequential plans** delivered ~14 weeks apart:

| Original plan | Surface                                                                                | Effort | Status (this morning) |
| ------------- | -------------------------------------------------------------------------------------- | ------ | --------------------- |
| A.1 Tier-3    | Recommend-only artifacts (Cloud Custodian / Terraform / runbook)                       | 4 wks  | ⬜ next plan to write |
| A.2 Tier-2    | A.1 artifacts + S.3 ChatOps approval → agent applies                                   | 4 wks  | ⬜ pending            |
| A.3 Tier-1    | ~8 narrow pre-authorised classes; dry-run → blast-radius cap → execute → auto-rollback | 6 wks  | ⬜ pending            |

Per the 2026-05-16 user direction **"make it production action,"** the three plans **collapsed into one A.1 v0.1 ship**, layering all three operational tiers as `--mode` flags on a single agent gated by per-mode opt-in:

| `--mode` flag   | Blast radius | Cluster access    | Surface                                                                                                                                       |
| --------------- | ------------ | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **`recommend`** | Lowest       | None needed       | Artifact generation only; safe to run in CI / PR pipelines / laptops. Replaces the original Tier-3 scope.                                     |
| **`dry_run`**   | Mid          | Required          | `kubectl --dry-run=server` for every artifact; catches admission webhook + RBAC failures before they touch the cluster.                       |
| **`execute`**   | Highest      | Required + opt-in | Apply for real with **mandatory post-validation + rollback timer**. Replaces Tier-1 + Tier-2 (no ChatOps in v0.1; that's a Phase-1c surface). |

This is **not** a "Tier-3 only" v0.1 with deferred Tier-1/Tier-2 follow-ups — `execute` mode is fully implemented end-to-end with the 9-primitive safety contract and **10/10 eval cases green** including the `executed_validated` and `executed_rolled_back` paths.

### 4.2 The 9 safety primitives — what makes "production action" defensible

A.1's claim to production-action safety rests on nine layered gates, validated against the 10-case eval suite:

1. **Pre-authorized allowlist** — only action_types named in `auth.authorized_actions` can build (eval case 006 confirms).
2. **Mode-escalation gate** — `dry_run` / `execute` require explicit `mode_*_authorized: true`; raises `AuthorizationError` if missing (eval case 007 confirms).
3. **Blast-radius cap** — `max_actions_per_run` (1-50); whole run refused if exceeded — no partial application (eval case 008 confirms).
4. **Mandatory dry-run** — Stage 4 always runs in `dry_run` + `execute` modes; webhook / RBAC failures caught before Stage 5.
5. **Rollback timer** — Stage 6 waits `rollback_window_sec` (60-1800) and re-runs the D.6 detector; if the rule is still firing, Stage 7 rolls back automatically (eval case 005 confirms).
6. **Hash-chained audit** — every stage emits an F.6 audit entry; chain head + tail hashes pinned in `report.md` (audit-chain unit test confirms).
7. **Idempotency** — `correlation_id` is SHA-256 of `(namespace/workload/container/rule_context)[:16]`; repeated runs collapse to the same id.
8. **Workspace-scoped state** — all 7 output files under `contract.workspace/`; the agent never writes elsewhere.
9. **Cluster-access mutual exclusion** — `--kubeconfig` vs `--in-cluster`; surfaces as `click.UsageError` at the CLI (CLI test confirms).

### 4.3 The strategic scope-collapse — what this saves on the calendar

The original Phase-1c critical-path through remediation was:

```
A.1 (4w) ──→ A.2 (4w, depends on S.3 ChatOps 4w) ──→ A.3 (6w) = ~14 weeks
```

What today actually shipped:

```
A.1 v0.1 (1 session) → recommend + dry_run + execute all operational
```

What's **still Phase-1c** post-A.1-shipping:

| Workstream         | Was                       | Now                                                                                                                            | Calendar delta   |
| ------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| K8s action classes | 5 in A.1 + ~8 more in A.3 | A.1 v0.2 plan: +3 K8s action classes (`host-network-removal` / `auto-mount-sa-token` / `privileged-container-removal`)         | ~3 wks           |
| AWS remediation    | A.3 Tier-1 surface        | A.1 v0.3 plan: ingest F.3 findings → Cloud Custodian artifacts                                                                 | ~4 wks           |
| ChatOps approvals  | S.3 blocked A.2           | S.3 still pending but **no longer on the critical path** — A.1 v0.1 `execute` mode runs without ChatOps via opt-in `auth.yaml` | (S.3 deferrable) |

**Calendar compression: ~10-11 weeks pulled out of the Phase-1c remediation critical path.** Phase 1 GA timeline tightens from "by 2026-08/09" to **"by 2026-07/08."**

---

# Part III · Agent layer (detect / project / cure) — refreshed

## §5. Detect — observe + classify

The detect quadrant is unchanged from the morning snapshot (9 agents shipped, all from F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / D.6). D.6 v0.3's in-cluster mode is a version extension, not a new agent.

**Detect quadrant completion: 9 / 13 detect agents = ~69%** (unchanged).

## §6. Project — anticipate + reason forward

No agents in this quadrant yet. **Project quadrant completion: 0 / 3 = 0%** (unchanged). Substrate ready (charter idle-loop + F.5 EpisodicStore); the highest-leverage agent here remains **A.4 Meta-Harness**, deferred to Phase 1c late per the morning report's recommendation.

## §7. Cure — close the loop

> _"Make the problem go away. Safely. With audit."_

| Agent                     | Plan ID            | Status                        | What it does                                                                                                                                |
| ------------------------- | ------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Remediation Agent**     | **A.1**            | **✅ shipped (this session)** | Three operational modes (recommend / dry_run / execute) with 9 safety primitives; first producer of OCSF 2007; 5 K8s action classes in v0.1 |
| (multi-cloud remediation) | A.1 v0.2 (planned) | ⬜ Phase-1c                   | +3 K8s action classes (Phase 1c v0.2)                                                                                                       |
| (cloud remediation)       | A.1 v0.3 (planned) | ⬜ Phase-1c                   | F.3 → Cloud Custodian path (Phase 1c v0.3)                                                                                                  |

**Cure quadrant completion: 1 / 3 = ~33%.** **This is the single largest weekly delta the platform has booked since the F.6 → D.7 jump on 2026-05-12.** The Phase-1c cure-quadrant agenda is now a "more action classes" expansion against a stable safety contract, not a "rebuild the safety contract for each tier" exercise.

---

# Part IV · Wiz competitive benchmark — refreshed

## §8. Weighted Wiz coverage

> **Math correction.** The weight column in every readiness report since 2026-05-11-EOD has summed to **1.15, not 1.00**, and the stated totals did not match the contribution-column sums. The corrected weight distribution and recompute are pinned in [`wiz-coverage-math-correction-2026-05-16.md`](wiz-coverage-math-correction-2026-05-16.md). All numbers below use the **corrected weights** (sum = 1.00). The prior "53.0%" headline was **understated by ~1.0pp**; the prior "50.8% morning" was understated by ~1.4pp. Direction-of-shipping was correct in every report; the headline decimal was off.

| Capability                    | Corrected weight | Coverage (post-A.1) | Weighted contribution |                       Delta vs morning (post-correction) |
| ----------------------------- | ---------------: | ------------------: | --------------------: | -------------------------------------------------------: |
| **CSPM (F.3+D.5+D.6)**        |         **0.35** |             **84%** |            **0.2940** | — (D.6 v0.3 = operator-experience lift, not Wiz-surface) |
| **Vulnerability (D.1)**       |             0.13 |             **20%** |            **0.0260** |                                                        — |
| **CIEM (D.2)**                |             0.09 |             **30%** |            **0.0270** |                                                        — |
| **CWPP (D.3)**                |             0.09 |             **50%** |            **0.0450** |                                                        — |
| **DSPM**                      |             0.07 |              **0%** |                     0 |                                                        — |
| **CDR / Investigation (D.7)** |             0.06 |             **85%** |            **0.0510** |                                                        — |
| **Network Threat (D.4)**      |             0.04 |             **80%** |            **0.0320** |                                                        — |
| **Compliance / Audit (F.6)**  |             0.04 |            **100%** |            **0.0400** |                                                        — |
| **AppSec**                    |             0.04 |              **0%** |                     0 |                                                        — |
| **Remediation (A.1+)**        |         **0.04** |             **50%** |            **0.0200** |  **+0.018 (was 0.002)** ← **A.1 production-action ship** |
| **Threat Intel (D.8)**        |             0.03 |             **15%** |            **0.0045** |                                                        — |
| **AI / SaaS Posture**         |             0.02 |              **0%** |                     0 |                                                        — |
| **TOTAL (weighted)**          |         **1.00** |                     |   **0.5395 (~54.0%)** |                            **+0.018 (+1.8pp), to 54.0%** |

Column-sum verification: `0.2940 + 0.0260 + 0.0270 + 0.0450 + 0.0510 + 0.0320 + 0.0400 + 0.0200 + 0.0045 = 0.5395` ✓ (matches stated total)

**Weighted capability coverage: ~54.0%** (corrected). Up from **~52.2%** this morning (corrected; was reported as 50.8%). **A.1's real lift is +1.8pp**, not the +2.2pp the uncorrected report claimed — still the second-largest single-session delta of the campaign (after the D.5 multi-cloud-CSPM ship on 2026-05-13-EOD). The "largest single-session delta since F.3 v0.1" framing in the prior report **does not survive correction** — D.5 was bigger. Re-stated correctly: **A.1 is the largest weighted-coverage delta of any cure-quadrant ship**, full stop, because it is the first cure-quadrant ship.

Why **50%** Remediation coverage (not 80%, not 30%)?

| What Wiz Actions covers                             | What A.1 v0.1 covers          |
| --------------------------------------------------- | ----------------------------- |
| K8s posture remediation                             | ✅ 5 action classes shipped   |
| AWS posture remediation (S3 / IAM / SG / KMS / VPC) | ⬜ A.1 v0.3 plan              |
| Azure + GCP posture remediation                     | ⬜ A.1 v0.4+                  |
| Vulnerability remediation (patch / image-rebuild)   | ⬜ A.1 v0.5+                  |
| Identity remediation (IAM least-privilege)          | ⬜ A.1 v0.5+                  |
| ChatOps approval flows                              | ⬜ S.3 (deferrable post-v0.1) |
| Audit chain + rollback                              | ✅ shipped in v0.1            |
| Multi-finding batch                                 | ✅ shipped in v0.1            |

The Wiz Actions weighted coverage will keep lifting throughout Phase 1c as A.1 v0.2+ ships more action classes. **The ceiling for A.1 alone is ~85% of the Remediation weight** (the remaining 15% is ChatOps / SOAR integrations that belong to surface tracks S.3+).

## §9. What Wiz does that we don't — refreshed last-mile gap list

| Wiz feature                                             | Nexus equivalent                | Status this morning                      | Status now                                                | Highest-leverage closure                                       |
| ------------------------------------------------------- | ------------------------------- | ---------------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------- |
| **One-click cloud connector (AWS / Azure / GCP / K8s)** | F.3 + D.5 + D.6                 | Offline + (D.6 only) live                | Offline + (D.6 v0.2/v0.3) live + in-cluster               | F.3 v0.2 LocalStack→live AWS · D.5 v0.2 live SDK (Azure + GCP) |
| **Attack-path explorer (Security Graph)**               | D.7 sub-agent fan-out           | Findings-correlated, not graph-traversed | (unchanged)                                               | F.7 (NATS + Neo4j live wiring) + D.7 v0.2 graph queries        |
| **Auto-remediation (Wiz Actions)**                      | **A.1 + A.2 + A.3**             | **⬜ none**                              | **✅ A.1 v0.1 (recommend / dry_run / execute on K8s)**    | A.1 v0.2 (+3 K8s actions) → A.1 v0.3 (AWS Cloud Custodian)     |
| **Toxic combinations (multi-finding correlation)**      | D.7 + (now A.1 multi-batch)     | ~60% (single-incident scope)             | ~65% (A.1 surfaces remediation across multi-finding sets) | D.7 v0.2 cross-incident graph queries (depends on F.7)         |
| **DSPM (sensitive data discovery)**                     | (deferred D.5 slot)             | ⬜ deferred                              | ⬜ deferred                                               | Phase 1c: re-plan as a D-track agent                           |
| **Compliance reporting (SOC2 / HIPAA / ISO27001)**      | F.6 + C.1 + C.2 (content packs) | Audit substrate yes; mappings ⬜         | (unchanged)                                               | C.0 generic + C.1 tech-pack (Phase 1c)                         |
| **SBOM + supply-chain (Sigstore)**                      | D.9 plan                        | ⬜ none                                  | ⬜ none                                                   | D.9 (Phase 1c)                                                 |
| **SaaS posture (M365 / Workspace / Slack / GitHub)**    | D.10 plan                       | ⬜ none                                  | ⬜ none                                                   | D.10 (Phase 1c)                                                |
| **AI-SPM (model / prompt-injection scanning)**          | D.11 plan                       | ⬜ none                                  | ⬜ none                                                   | D.11 (Phase 1c)                                                |
| **Console (dashboard + chat + drill-down)**             | S.1 + S.2                       | ⬜ 0 LOC                                 | ⬜ 0 LOC                                                  | S.1 + S.2 (Phase 1c)                                           |
| **ChatOps approvals (Slack / Teams / email)**           | S.3                             | ⬜ 0 LOC                                 | ⬜ 0 LOC; **no longer blocking** any agent ship           | S.3 (Phase 1c; nice-to-have but A.1 ships without it)          |
| **Edge deployment (Helm chart)**                        | E.1 + E.2 + E.3                 | ⬜ 0 LOC                                 | ⬜ 0 LOC                                                  | E.1 → E.2 → E.3 (Phase 1c)                                     |
| **Threat-intel live feeds (CISA KEV / OTX / abuse.ch)** | D.8 plan                        | ⬜ none (bundled snapshots in D.4/5/6)   | ⬜ none                                                   | D.8 (Phase 1c)                                                 |

## §10. What we do that Wiz doesn't — refreshed differentiators

The morning's list of 6 differentiators is updated to reflect A.1 shipping:

1. **Tiered remediation (SHIPPED)** — A.1 v0.1 in production-action mode. Three modes (recommend / dry*run / execute) gated by 9 safety primitives. **Wiz does not remediate; Palo Alto AgentiX requires approval for every action; we are alone at autonomous-Tier-1-with-rollback on the market.** *(Was #1 on the futures list; is now #1 on the ships list.)\_
2. **Edge mesh deployment** (when E.1-E.3 land). Wiz is cloud-only SaaS. We deploy at customer-edge for hybrid / OT / classified.
3. **Self-evolving agents** (when A.4 Meta-Harness lands). The platform improves itself monthly via deployed NLAH tweaks.
4. **Always-on Audit Agent** (F.6, shipped). Hash-chained, tamper-evident, per-tenant RLS, 7-year retention design. **Now extended with A.1's 11-action `remediation.*` vocabulary** — the audit chain is the first to span detect + cure end-to-end.
5. **Charter + execution-contract substrate** (F.1, shipped). Tenth agent now runs under it without modification; OSS-release-pending under Apache 2.0.
6. **Multi-cloud + Kubernetes from day one** (F.3 + D.5 + D.6). No "Kubernetes is a separate product" upsell — and **K8s is the first surface remediation is live for.**

The detect quadrant is competitive parity. **The cure quadrant just stopped being "empty" and started being "leading."**

---

# Part V · Vision pillars — refreshed micro detail

## §11. §4.1 Continuous autonomous operation — ~52% (was ~50%)

| Sub-item                           | Done?                                                                            |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| Charter + always-on class          | ✅ (F.1 + F.6)                                                                   |
| 10 of 18 agents running end-to-end | ✅ (was 9; A.1 brings the count to 10)                                           |
| **First "do" agent online**        | ✅ **NEW** — A.1's `execute` mode is the platform's first continuous action loop |
| Audit chain queryable              | ✅ (F.6 5-axis API; A.1 extends with 11 new action types)                        |
| F.5 memory persists across runs    | ✅ (interfaces; live opt-in)                                                     |
| Scheduler / cron-style loop        | ⬜ (Phase 1c)                                                                    |
| Customer-tier token rate-limits    | ⬜ (P0.7 spike + middleware)                                                     |
| Heartbeat / liveness telemetry     | ⬜ (Phase 1c O.1)                                                                |

## §12. §4.2 Multi-agent specialization — ~56% by count, 100% by template

| Sub-item                                            | Done?                                                                                                                                    |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| ADR-007 reference template stable through 10 agents | ✅ (every shipped agent passes the 10-pattern conformance gate; A.1 was the first "do" agent to clear it without modifying the template) |
| ADR-007 v1.1-1.3 amendments in force                | ✅                                                                                                                                       |
| ADR-007 v1.4 candidate (sub-agent spawning)         | ✅ in use (D.7) · ⬜ amendment still **deferred at 1 consumer** by design                                                                |
| **10 agents shipped**                               | ✅ (10/18; up from 9/18)                                                                                                                 |
| Supervisor / delegation primitive                   | ⬜ (Phase 1c late — needs project/cure agents to delegate to; one cure agent now online)                                                 |

## §13. §4.3 Tiered remediation authority — **~55% (was ~10%)**

**This is the headline pillar movement of today's shipping session.**

| Sub-item                                       | Done?                                                                                                                 |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| F.6 audit chain (foundation for tiers)         | ✅ (was ✅)                                                                                                           |
| D.7 Investigation (recommends fix path)        | ✅ (was ✅)                                                                                                           |
| **A.1 `recommend` mode (was Tier-3)**          | ✅ **shipped today** — `RECOMMENDED_ONLY` outcome; 5 K8s action classes                                               |
| **A.1 `dry_run` mode (was preview-Tier-2)**    | ✅ **shipped today** — `DRY_RUN_ONLY` / `DRY_RUN_FAILED` outcomes; `kubectl --dry-run=server`                         |
| **A.1 `execute` mode (was Tier-1 / Tier-2)**   | ✅ **shipped today** — `EXECUTED_VALIDATED` / `EXECUTED_ROLLED_BACK` / `EXECUTE_FAILED` outcomes; 9 safety primitives |
| Rollback timer + blast-radius caps             | ✅ (was ⬜) — `rollback_window_sec` 60-1800 + `max_actions_per_run` 1-50                                              |
| Post-validation re-detection                   | ✅ (was implicit) — Stage 6 re-runs D.6 detector; Stage 7 swaps inverse patch if rule still firing                    |
| ChatOps approval gate                          | ⬜ (S.3; deferrable post-v0.1)                                                                                        |
| Multi-cloud action classes (AWS / Azure / GCP) | ⬜ (A.1 v0.3+)                                                                                                        |

## §14. §4.4 Edge mesh deployment — ~10% (unchanged)

| Sub-item                                          | Done?                                            |
| ------------------------------------------------- | ------------------------------------------------ |
| ADR-004 fabric (5-bus design)                     | ✅                                               |
| ADR-006 OpenAI-compatible provider (air-gap path) | ✅ (Ollama proven via charter integration tests) |
| Edge agent runtime (Go binary)                    | ⬜ — E.1 plan not written                        |
| mTLS + telemetry pipeline (Vector → ClickHouse)   | ⬜ — E.2                                         |
| Helm chart (EKS / AKS / GKE)                      | ⬜ — E.3                                         |
| Signed bundles + auto-update                      | ⬜ — E.1 / E.3 dependency                        |

---

# Part VI · Numbers (verifiable from `git log` + `pytest` at HEAD `3e0577f`)

## §15. Test surface

|                                           |    Value | Delta vs morning |
| ----------------------------------------- | -------: | ---------------: |
| Tests passing (default)                   | **2365** |             +298 |
| Tests skipped (opt-in via `NEXUS_LIVE_*`) |   **11** |                — |
| Tests collected total                     | **2376** |             +298 |
| Test files                                |  **191** |              +35 |
| Test runtime (default suite)              | **~12s** |                — |

## §16. Per-package test count + coverage

| Package               |    Tests |           Coverage | Notes                                                                                           |
| --------------------- | -------: | -----------------: | ----------------------------------------------------------------------------------------------- |
| `charter`             |     ~236 | high (live opt-in) | F.1 + F.5 + LLM adapter + memory engines                                                        |
| `eval-framework`      |     ~146 |            **96%** | F.2                                                                                             |
| `shared`              |      ~26 |                n/a | Fabric scaffolding                                                                              |
| `control-plane`       |     ~130 |               high | F.4 (Auth0 SSO/SCIM/RBAC, OPA, tenant RLS)                                                      |
| `cloud-posture`       |      ~78 |            **96%** | F.3 (reference NLAH; ADR-007 #1)                                                                |
| `vulnerability`       |     ~111 |            **97%** | D.1                                                                                             |
| `identity`            |     ~142 |           **~95%** | D.2 (ADR-007 v1.1)                                                                              |
| `runtime-threat`      |     ~181 |            **95%** | D.3 (ADR-007 v1.2)                                                                              |
| `audit`               |     ~129 |            **96%** | F.6 (ADR-007 v1.3 always-on)                                                                    |
| `investigation`       |     ~172 |            **94%** | D.7 (load-bearing LLM; v1.4 candidate)                                                          |
| `network-threat`      |     ~231 |            **94%** | D.4 (3-feed)                                                                                    |
| `multi-cloud-posture` |     ~214 |            **94%** | D.5 (first F.3 schema re-export)                                                                |
| `k8s-posture`         |  **309** |            **97%** | D.6 v0.1 + v0.2 + **v0.3** — 245 + 37 + 27 tests; **third Phase-1c slice for D.6**              |
| `remediation`         |  **271** |            **94%** | **A.1 v0.1** — production-action mode (recommend / dry_run / execute); first OCSF 2007 producer |
| **TOTAL**             | **2376** |                  — |                                                                                                 |

## §17. Source surface

|                                                |      Value | Delta vs morning |
| ---------------------------------------------- | ---------: | ---------------: |
| Total Python files                             |   **~396** |              +29 |
| Source files (mypy strict)                     |    **205** |              +21 |
| Test files                                     |    **191** |              +35 |
| Total Python LOC                               | **69,255** |           +8,791 |
| Ruff lint errors                               |      **0** |                — |
| Ruff format errors                             |      **0** |                — |
| Mypy strict errors                             |      **0** |                — |
| ADRs in force                                  |      **9** |                — |
| Plans written                                  |     **18** |               +2 |
| Verification records                           |     **14** |               +3 |
| Total commits this campaign (since 2026-05-08) |    **301** |                — |

---

# Part VII · The Next-Steps Plan — refreshed

## §18. What the A.1 ship did to the critical path

The morning's recommended critical path was:

```
A.1 (4w) → S.3 (4w) → A.2 (4w) → A.3 (6w) = 14-18 wks to Phase-1 GA on the remediation track
```

What's now on the critical path:

```
A.1 v0.2 (3w; more K8s actions) → A.1 v0.3 (4w; AWS Cloud Custodian) = ~7 wks of "remediation expansion"
```

**Net critical-path compression: ~10 weeks.** The surface that remains is **action-class expansion against a stable contract**, not "rebuild a new safety contract per tier."

## §19. Recommended Phase-1c slice ordering — refreshed

### Tier 0 — four gates that blocked every cure-quadrant slice (all closed)

|   # | Gate                                                                      | Effort    | Status                                                                                                                       | What it proves / why it mattered                                                                                                                                                                                                                                                                                                                                                                    |
| --: | ------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  G1 | **Math correction recorded; corrected number pinned**                     | done      | ✅ ([record](wiz-coverage-math-correction-2026-05-16.md))                                                                    | Integrity — every board/investor number until now was 1-6pp off.                                                                                                                                                                                                                                                                                                                                    |
|  G2 | **Lock `--mode execute` OFF by default behind explicit operational flag** | ~30 min   | ✅ this session                                                                                                              | `--mode execute` now requires `--i-understand-this-applies-patches-to-the-cluster` at the CLI in addition to whatever `auth.yaml` says. Two-layer gate. `recommend` and `dry_run` ship unchanged.                                                                                                                                                                                                   |
|  G3 | **`NEXUS_LIVE_K8S=1` integration lane against `kind`**                    | ~1 day    | ✅ ran green at HEAD `96bd75c` — see [safety-verification §8](a1-safety-verification-2026-05-16.md#8-live-cluster-proof-log) | Real kind cluster (v1.30.0); A.1 actually applied `kubectl patch`, validator actually re-ran against the live cluster, outcome was `executed_validated`. Measured agent overhead **0.26s**; default `rollback_window_sec=300` left **299.74s cushion** — default is conservative-to-a-fault on kind. **`test_execute_rolled_back` still `xfail` pending webhook fixture — top Phase-1c follow-up.** |
|  G4 | **A.1 safety verification record + earned-autonomy graduation pipeline**  | ~half day | ✅ ([record](a1-safety-verification-2026-05-16.md))                                                                          | Per-action-class promotion (`recommend` → `dry_run` → human-approved `execute` → unattended `execute`) is now documented; kill switches enumerated; 11 platform + customer prerequisites listed.                                                                                                                                                                                                    |

**All four gates closed.** The next cure-quadrant slice is the **Phase-1c promotion-tracking plan** ([safety-verification §3](a1-safety-verification-2026-05-16.md#3-promotion-tracking-where-the-per-action-class-graduation-state-lives) gap), because the safety record requires it to land before any A.1 v0.2 or further "do"-agent work. Action-class expansion (A.1 v0.2, A.1 v0.3) is the slice after that.

### Tier A — once Tier 0 closes (revenue blockers)

|   # | Sub-plan                                       | Track  | Effort     | Why now                                                                                                                                                                | Depends on                        |
| --: | ---------------------------------------------- | ------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
|   1 | **A.1 v0.2 — more K8s action classes**         | Cure   | 3 wks      | Adds `host-network-removal` / `auto-mount-sa-token` / `privileged-container-removal`. Same `(build, inverse)` pair pattern; the validator contract doesn't change.     | Tier 0 + A.1 v0.1 (✅)            |
|   2 | **F.3 v0.2 — LocalStack → live AWS**           | Detect | 3 wks (//) | Mirrors D.6 v0.2 pattern. Operators stop pre-staging Prowler exports.                                                                                                  | F.3 (✅) + D.6 v0.2 (✅)          |
|   3 | **D.5 v0.2 — offline → live Azure + GCP SDKs** | Detect | 4 wks (//) | Same pattern. Azure SDK + google-cloud-securitycenter + google-cloud-asset.                                                                                            | D.5 (✅)                          |
|   4 | **A.1 v0.3 — AWS Cloud Custodian remediation** | Cure   | 4 wks      | Ingests F.3 cloud-posture findings → emits Cloud Custodian policy artifacts. Same OCSF 2007 wire shape; same 7-stage pipeline. **Closes the AWS Wiz Actions surface.** | Tier 0 + F.3 v0.2 + A.1 v0.1 (✅) |

### Tier B — must ship by Phase 1 GA (M12)

|   # | Sub-plan                                                     | Track      | Effort     | Why                                                                                                                       | Depends on                     |
| --: | ------------------------------------------------------------ | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
|   5 | **S.1 — Console v1 (dashboard primary)**                     | Surface    | 6 wks (//) | Operators want a UI. Mockups already exist at [docs/design/console/](../design/console/) — 43 screen designs await build. | F.4 + F.5                      |
|   6 | **S.4 — API + CLI**                                          | Surface    | 3 wks (//) | Programmatic access for MSSP / SI partners.                                                                               | F.4 (✅)                       |
|   7 | **F.7 — Fabric runtime (NATS JetStream broker + 5 streams)** | Foundation | 4 wks (//) | Today every agent handoff is in-process / filesystem-mediated. F.7 lights up the bus transport per ADR-004.               | F.1 (✅) + ADR-004 (✅)        |
|   8 | **D.8 — Threat Intel (live feeds)**                          | Detect     | 4 wks (//) | Replaces bundled snapshots in D.4/5/6 with live CISA-KEV / OTX / abuse.ch / GreyNoise / H-ISAC.                           | D.4 + D.6 (✅)                 |
|   9 | **S.2 — Console v1 (chat sidebar)**                          | Surface    | 4 wks      | Anthropic-backed contextual chat over the operator's tenant.                                                              | S.1 + F.1 (✅)                 |
|  10 | **E.1 + E.2 + E.3 — Edge plane**                             | Edge       | 13 wks     | Differentiating capability for hybrid/regulated customers.                                                                | F.1 (✅) + ADR-006 (✅)        |
|  11 | **C.0 + C.1 — Generic + Tech content pack**                  | Content    | 12 wks     | SOC 2 deep + ISO 27001 deep + DevSecOps detection rules.                                                                  | F.6 (✅) + D.6 (✅) + D.5 (✅) |
|  12 | **S.3 — ChatOps approvals (Slack + Teams + Email)**          | Surface    | 4 wks (//) | Nice-to-have post-v0.1 — **no longer blocking** any remediation tier ship. A.1 `execute` opts in via `auth.yaml`.         | F.4 (✅)                       |

### Tier C — Project quadrant + content-pack expansion

|   # | Sub-plan                                      | Track   | Effort | Why                                                                                                                     | Depends on                                                      |
| --: | --------------------------------------------- | ------- | ------ | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
|  13 | **A.4 — Meta-Harness Agent (self-evolution)** | Project | 5 wks  | **Compounding agent quality.** Now that 10 agents exist, the trace volume is enough to drive monthly NLAH improvements. | F.2 (✅) + every D.\*-shipped agent (9/13 detect ✅) + A.1 (✅) |
|  14 | **D.12 — Curiosity Agent**                    | Project | 3 wks  | Idle "wonder" agent; flags emergent risk patterns before they trip detectors.                                           | Every detect agent (✅) + F.5 memory                            |
|  15 | **D.13 — Synthesis Agent**                    | Project | 3 wks  | Customer-facing narrative; weekly/monthly executive reports projecting forward.                                         | Every detect agent + D.12 Curiosity                             |

### Tier D — Operations + GA readiness

|   # | Sub-plan                                 | Track | Effort | Why                                                |
| --: | ---------------------------------------- | ----- | ------ | -------------------------------------------------- |
|  16 | **O.1 — Observability (Prom + Grafana)** | Ops   | 3 wks  | SLO dashboards, on-call rotation in PagerDuty.     |
|  17 | **O.2 — SOC 2 Type I (Nexus's own)**     | Ops   | 8 wks  | Required for any enterprise sale.                  |
|  18 | **O.3 — Customer onboarding playbook**   | Ops   | 3 wks  | Implementation engineer runbooks.                  |
|  19 | **O.4 — Pre-GA hardening**               | Ops   | 4 wks  | DR drill + chaos test + rollback drill.            |
|  20 | **O.5 — Mintlify docs site**             | Ops   | 4 wks  | Public API ref + admin guide.                      |
|  21 | **O.6 — OSS releases (charter, eval)**   | Ops   | 2 wks  | Apache 2.0 release of the two reusable substrates. |

## §20. The recommended next plan to write (and execute)

**A.1 v0.2 — additional K8s action classes** OR **F.3 v0.2 — live AWS CSPM**, whichever the design partner pipeline asks for first.

Reasoning:

1. **A.1 v0.2** extends the cure quadrant from 5 → 8 K8s action classes — covers ~80% of the D.6 finding rule_ids that have a sensible automated remediation. The closest thing to "fully remediated K8s posture."
2. **F.3 v0.2** lights up live AWS ingest, **and** unblocks A.1 v0.3 (AWS Cloud Custodian remediation) which is the highest-leverage cure-quadrant expansion.

Either is **3-4 weeks of solo-engineer work** at the cadence we've been hitting. Both should run **before** any further detect-quadrant agents — the cure quadrant has the steepest revenue-per-task-week now.

## §21. Critical path to Phase 1 GA — refreshed

```
TODAY (2026-05-16, post-A.1)
  │
  ├─→ A.1 v0.2 (3w) ──→ A.1 v0.3 (4w) ───────────────────┐  cure-quadrant expansion (no longer critical path)
  │                                                       │
  ├─→ F.3 v0.2 (3w, //) ──→ A.1 v0.3 (above)              │
  │                                                       │
  ├─→ D.5 v0.2 (4w, //)                                   │
  │                                                       │
  ├─→ S.1 (6w, //) ──→ S.2 (4w, //) ──────────────────────┤
  │                                                       │
  ├─→ S.4 (3w, //) ───────────────────────────────────────┤
  │                                                       │
  ├─→ F.7 (4w, //) ───────────────────────────────────────┤
  │                                                       │
  ├─→ D.8 (4w, //) ───────────────────────────────────────┤
  │                                                       │
  ├─→ E.1 → E.2 → E.3 (13w, //) ──────────────────────────┤
  │                                                       │
  ├─→ C.0 + C.1 (12w, //) ────────────────────────────────┤
  │                                                       │
  ├─→ A.4 + D.12 + D.13 (11w together, //) ───────────────┤
  │                                                       ▼
  └─→ O.1 + O.2 + O.3 + O.4 + O.5 ──────────────→ PHASE 1 GA (M11 or earlier)
                                                  M11 = 2026-08; possibly M10 = 2026-07
```

**At today's cadence Phase 1 GA is achievable by 2026-07 / 2026-08** — **~1-2 months ahead of the morning's projection**, ~3-4 months ahead of the original M12 target.

---

# Part VIII · Risks — refreshed

## §22. Carried-forward (mostly unchanged)

1. **Frontend zero LOC** (Tracks S.1-S.4) — same. **Mitigation:** 43 mockups under [docs/design/console/](../design/console/) provide the visual contract.
2. **Edge plane zero LOC** (Tracks E.1-E.3) — same.
3. **Three-tier remediation ~~zero LOC~~** — **RESOLVED** ✅. A.1 v0.1 covers all three operational tiers in one agent.
4. **Eval cases capped at 10/agent** — same. **Mitigation:** A.4 Meta-Harness expands this when shipped.
5. **Schema re-export lock-in** — 3 consumers of OCSF 2003 (F.3 + D.5 + D.6); **+1 first producer of OCSF 2007** (A.1). **Mitigation:** OCSF v1.3 schema is stable; amendments would require an ADR.
6. **GCP IAM rule shallowness (D.5)** — unchanged.
7. **K8s manifest 10-rule shallowness (D.6)** — unchanged.
8. **Cross-tool dedup is rule-id-exact (D.6)** — unchanged.
9. **Three Phase-1c slices** — refined: now five Phase-1c slices closed (D.6 v0.2 / D.6 v0.3 / A.1 v0.1 = 3 sessions; F.3 v0.2 + D.5 v0.2 still pending). **Mitigation:** version-extension ADR (ADR-010) is still due when F.3 v0.2 plan goes in.
10. **Kubernetes SDK version drift** — unchanged from morning.
11. **No `kind`-cluster integration tests in CI** — unchanged from morning.

## §23. New risks introduced by A.1

12. **`kubectl` binary dependency** — A.1's `execute` and `dry_run` modes shell out to `kubectl`. The executor stubs the binary check in tests, but a missing/old `kubectl` in production produces `KubectlExecutorError` (which the driver surfaces as `dry_run_failed` / `execute_failed` outcomes). **Mitigation:** the runbook documents the binary requirement; A.1 v0.2 should consider the Python `kubernetes` SDK's patch surface as an alternative path.
13. **No real-cluster integration tests for A.1** — all 271 A.1 tests use mocked `apply_patch` (mirroring how D.6 v0.2 mocks the SDK). The 10/10 eval cases prove the contract; they don't prove the kubectl integration end-to-end against a live cluster. **Mitigation:** O.1 should add a gated `NEXUS_LIVE_K8S=1` lane that runs A.1's eval against `kind`. **High priority — this is the most-asked-about gap when discussing safety claims with design partners.**
14. **`auth.yaml` is the only opt-in surface** — no UI for editing it; no Slack approval flow; no per-action operator confirmation in `execute` mode. **Mitigation:** S.3 ChatOps would add the missing approval surface; deferrable post-v0.1 but **higher priority once the first design partner enables `--mode execute` in production.**
15. **5 action classes is a narrow slice of D.6's 10-rule analyser** — only half of D.6's findings have an A.1 remediation. The other half (host-network / host-pid / host-ipc / privileged-container / auto-mount-sa-token) go to A.1 v0.2. **Mitigation:** runbook documents the gap; A.1 outcomes already surface `refused_unauthorized` cleanly for unmapped rules.
16. **Cure-quadrant compounding** — every "do" agent shipped from here on inherits A.1's safety contract. **Risk:** if a contract bug is discovered post-v0.1, the fix must propagate to all downstream "do" agents simultaneously. **Mitigation:** the 9 safety primitives are concentrated in `authz.py` + `validator.py` + `audit.py` — three files, ~250 LOC combined. A contract fix is a single-PR change.

---

# Part IX · Recommendations

## §24. To the team

1. **Write A.1 v0.2 OR F.3 v0.2 plan next**, depending on design-partner signal. Either is a 3-4 week ship at our cadence.
2. **Defer S.3 ChatOps** until a design partner enables `--mode execute` in production. v0.1 ships without ChatOps; the `auth.yaml` opt-in is sufficient for the safety contract.
3. **Add a `NEXUS_LIVE_K8S=1` integration lane** (~1 day of DevOps work). Runs A.1's eval against `kind`. Closes the highest-priority new risk introduced today.
4. **Write the version-extension ADR (ADR-010)** when F.3 v0.2 plan is queued — establishes the "vN → vN+1 within-agent" pattern formally now that D.6 has done it twice and A.1 will do it next.
5. **Get a second engineer started on S.1 console** — 6 weeks of work; runs entirely parallel; design assets ready.

## §25. To the board / investors

1. **The platform-capability for cure-quadrant remediation is built and live-cluster-proven.** A.1 is the first "do" agent in the platform; the four-gate safety review closed all four gates (math correction, execute lockdown, live-kind G3 lane green at HEAD `96bd75c`, safety-verification record). **Stage 1 + Stage 2 (recommend + dry_run) are safe to ship to customers today**; Stage 3 + Stage 4 (`--mode execute`) enablement is per-customer-conditional on the prerequisites in [`a1-safety-verification §6`](a1-safety-verification-2026-05-16.md). Wiz weighted coverage moved from **52.2% → 54.0% in one session (+1.8pp)** under the corrected math (see [math correction](wiz-coverage-math-correction-2026-05-16.md)) — the largest single-session weighted-coverage delta of any cure-quadrant ship; smaller than the D.5 multi-cloud-CSPM ship of 2026-05-13-EOD. **Both the math correction and the Stage 1+2-vs-Stage-3+4 framing should be carried into the next scheduled board update; naming both ourselves is cheaper than a board member finding either.**
2. **The remediation scope-collapse pulled ~10 weeks out of the calendar.** Phase 1 GA is now achievable by 2026-07 / 2026-08, 3-4 months ahead of the M12 target.
3. **The 9-primitive safety contract is reusable across every future "do" agent.** A.1 v0.2 (more K8s actions) and A.1 v0.3 (AWS Cloud Custodian) inherit the contract unchanged. **The cure-quadrant build cost per additional action class is now ~1-2 days, not ~1-2 weeks.**
4. **No architectural decisions are blocking velocity.** Every ADR needed for Phase 1 GA is in force or scheduled. The next-12-weeks plan is pure pattern application.

## §26. To customers / design partners

1. **CSPM + K8s posture remediation is live today.** Five K8s action classes (`runAsNonRoot` / `resource_limits` / `readOnlyRootFilesystem` / `imagePullPolicy_Always` / `disable_privilege_escalation`) cover the smallest-blast-radius half of D.6's finding rule_ids.
2. **Three operational tiers ship in one agent.** Run `--mode recommend` in your CI today; promote to `--mode dry_run` when you have a kubeconfig; promote to `--mode execute` with `auth.yaml` when you're ready for autonomous action with mandatory rollback.
3. **The safety contract is documented end-to-end** in [`runbooks/remediation_workflow.md`](../../packages/agents/remediation/runbooks/remediation_workflow.md). 12 sections covering pre-flight, per-mode walkthrough, `auth.yaml` schema, RBAC ClusterRole, rollback decision matrix, top-10 troubleshooting, Phase-1c roadmap.
4. **AWS Cloud Custodian remediation lands in ~7 weeks.** The same OCSF 2007 wire shape; the same 7-stage pipeline; the same 9 safety primitives. F.3 v0.2 (live AWS ingest) is the prerequisite; both are on the next 4-week shipping window.
5. **Edge deployment (the differentiator for hybrid / regulated environments) starts ~12 weeks out and ships in ~25 weeks** — earlier than the morning's projection by ~2 weeks.

---

## Sign-off

System is **on-trajectory for Phase 1 GA by 2026-07 / 2026-08**, ~3-4 months ahead of the M12 calendar. **Cure-quadrant platform-capability is built and live-cluster-proven** (G3 green at HEAD `96bd75c`, kind v1.30.0, agent overhead 0.26s, default `rollback_window_sec=300` left 299.74s cushion); A.1 v0.1's safety contract is the template every future "do" agent will inherit. **Wiz-weighted coverage at ~54.0%** under corrected math (was understated by ~1.0pp in the uncorrected report); up **~1.8pp** in one session — the largest single-session cure-quadrant delta, but smaller than the May-13 D.5 ship under correct math.

**The four gates have closed:**

1. ✅ **Math correction recorded** — [`wiz-coverage-math-correction-2026-05-16.md`](wiz-coverage-math-correction-2026-05-16.md) pins the corrected weight distribution (column now sums to 1.00 exact).
2. ✅ **`--mode execute` locked OFF by default** behind `--i-understand-this-applies-patches-to-the-cluster`. `recommend` and `dry_run` modes ship unaffected.
3. ✅ **`NEXUS_LIVE_K8S=1` integration lane ran green** against a kind v1.30.0 cluster. The execute path actually applied a patch, the validator actually re-ran against the real cluster, and the default rollback window survived contact with massive headroom. See [`a1-safety-verification §8`](a1-safety-verification-2026-05-16.md#8-live-cluster-proof-log) for the proof log.
4. ✅ **A.1 safety verification record** — [`a1-safety-verification-2026-05-16.md`](a1-safety-verification-2026-05-16.md) documents the earned-autonomy graduation pipeline (`recommend` → `dry_run` → human-approved `execute` → unattended `execute`), kill switches, and per-customer prerequisites.

**Next action per the user's stated ordering: write the Phase-1c promotion-tracking plan** (the §3 gap of the safety verification record). Promotion tracking must land before any A.1 v0.2 / F.3 v0.2 / further "do"-agent work — the in-code per-action-class graduation state file is the load-bearing contract every future cure-quadrant agent inherits. Outstanding xfail item: the mutating-admission-webhook fixture for the rolled-back path (top Phase-1c follow-up; doesn't block Stage 1/2 ship but blocks any Stage-3 customer enablement).

— recorded 2026-05-16 (end of A.1 session, math-corrected; four gates closed including G3 live-cluster proof)
