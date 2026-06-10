# D.2 Identity (CIEM) v0.2 — verification record + CYCLE CLOSURE (2026-06-10)

> **D.2 v0.2 Milestone 7, Task 24 — the final task.** Closes Cycle 4 of the strict-serial
> detection track (after F.3 #267, D.5 #288, D.1 #312). **This is the cycle where the
> ADR-007 third-consumer charter hoist FINALLY fired** — the first substrate-seal break,
> intentional and minimal.

## §1. Cycle summary

D.2 took multi-cloud **Identity / CIEM** from AWS-IAM-only (v0.1, ~30%) to **Level 2**:
**live AWS IAM** (via the hoisted `CredentialResolver`) + **net-new live Azure AD / Entra**
(Microsoft Graph) + **basic SAML/OIDC federation forensics**, emitting OCSF v1.3 Detection
Findings (`class_uid 2004`). The defining moment: **3 of F.3's 5 #266 patterns hoisted into
`nexus-charter`** (Patterns E + D + A, Tasks 2–4, three SAFETY-CRITICAL PRs), then adopted by
their origin agents **and** identity — the canonical ADR-007 third consumer. 24 tasks, 7
milestones, **0 failed** at every step.

## §2. 24-task execution table

| #   | Task                                                     | PR       | Risk                |
| --- | -------------------------------------------------------- | -------- | ------------------- |
| 1   | Bootstrap (version + ADR-010 + smoke)                    | #315     | LOW                 |
| 2   | Hoist **Pattern E** (partial-scan degradation) → charter | #343     | **SAFETY-CRITICAL** |
| 3   | Hoist **Pattern D** (live-eval lane gating) → charter    | #344     | **SAFETY-CRITICAL** |
| 4   | Hoist **Pattern A** (CredentialResolver) → charter       | #345     | **SAFETY-CRITICAL** |
| 5   | Adopt CredentialResolver in identity aws_iam             | #346     | LOW                 |
| 6   | Live AWS IAM policy enumeration                          | #347     | LOW                 |
| 7   | Access Analyzer via charter resolver                     | #348     | LOW                 |
| 8   | AWS IAM partial-scan degradation (Pattern E)             | #349     | LOW · **M3 closed** |
| 9   | Azure AD CredentialResolver from charter                 | #350     | LOW                 |
| 10  | Microsoft Graph users + groups                           | #351     | LOW                 |
| 11  | Service principals + managed identities                  | #352     | LOW                 |
| 12  | Azure AD partial-scan degradation (Pattern E)            | #353     | LOW · **M4 closed** |
| 13  | SAML federation trust detection                          | #354     | LOW                 |
| 14  | OIDC federation trust detection                          | #355     | LOW                 |
| 15  | Federation OCSF 2004 emission                            | #356     | LOW · **M5 closed** |
| 16  | `NEXUS_LIVE_IDENTITY_AWS` lane (Pattern D)               | #357     | LOW                 |
| 17  | `NEXUS_LIVE_IDENTITY_AZURE` lane (Pattern D)             | #358     | LOW                 |
| 18  | **Live end-to-end IAM pipeline (WI-I4 HARD)**            | #359     | LOW                 |
| 19  | Lane coexistence (8 platform lanes)                      | #360     | LOW · **M6 closed** |
| 20  | WI-I7 cross-agent OCSF 2004 + charter sweep              | #361     | LOW                 |
| 21  | Per-cloud runbooks + README v0.2                         | #362     | LOW                 |
| 22  | Per-cloud CIEM coverage notes                            | #363     | LOW                 |
| 23  | WI-I8 hoist-completion doc                               | #364     | LOW                 |
| 24  | **Verification + closure**                               | _(this)_ | LOW · **M7 closed** |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                                                       | Honored                                                                                   |
| --- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Q1  | Charter hoist **A + D + E** (drop C, defer B); 3 SAFETY-CRITICAL PRs E→D→A | Tasks 2–4; B + C deferred with triggers ([WI-I8 doc](f-3-hoist-completion-2026-06-10.md)) |
| Q2  | AWS IAM **live** (users+roles+policies+groups + Access Analyzer)           | Tasks 5–8                                                                                 |
| Q3  | Azure AD users+groups+SPs+MIs (Conditional Access + PIM → v0.3)            | Tasks 9–12                                                                                |
| Q4  | GCP IAM CIEM → v0.3                                                        | out of scope, documented                                                                  |
| Q5  | Federation **basic** trust detection (deep chains → v0.3)                  | Tasks 13–15                                                                               |
| Q6  | Single-account (AWS) / single-tenant (Azure)                               | enforced throughout                                                                       |
| Q7  | Effective-permissions simulator → v0.3                                     | built-but-undriven; documented                                                            |

## §4. Gates passed

- **Tool-proxy hard boundary (ADR-016):** `test_tool_import_guard` 16 passed — the charter
  hoists touched substrate but the NLAH-cycle boundary held.
- **ADR-007 v1.7 + ADR-017:** inherited per task; NLAH unchanged (no scope drift); identity
  NLAH already grade A (backfill #328).
- **OCSF 2004 byte-identical (WI-I5):** the offline eval stayed byte-identical every task; the
  new `federation` finding type rides the separate `federation_to_findings` path.
- **WI-I4 (HARD):** the live end-to-end pipeline runs on every push (moto) + gated live (#359).
- **WI-I7:** the largest cross-agent sweep — all OCSF 2004 emitters + all charter-hoist
  consumers green after the hoist ([Task 20](d-2-identity-v0-2-cross-agent-sweep-2026-06-10.md)).
- **Substrate seal:** RED only for Tasks 2–4 (the intentional hoists); EMPTY for all of 5–24.
- **Final full-repo run: 5384 passed, 57 skipped (env-gated live lanes), 0 failed.**

## §5. Honest findings (WI-I3 discipline)

- **CIEM is breadth, not depth at v0.2.** AWS IAM ~35–40%, Azure AD ~20–25% `[estimate]`,
  measured **separately, no aggregate** ([coverage notes](d-2-identity-v0-2-ciem-coverage-2026-06-10.md)).
  The defining CIEM capability — **computed effective permissions** — is **not in v0.2**; the
  IAM simulator is built + tested but undriven, and Azure RBAC effective-perms is unscoped.
  Both are the L3 residual (Q7), the single largest remaining gap per the benchmark.
- **Admin detection is heuristic** (managed-policy-ARN match), not statement-level — it can
  miss admin-via-custom-policy / admin-via-inline. The enumerated policy documents (Task 6)
  are captured for the v0.3 statement-level pass but not yet consumed.
- **Azure OIDC is tenant-level only** — per-app workload identity federation
  (`federatedIdentityCredentials`, e.g. GitHub → managed identity) is v0.3 (WI-I6).

## §6. Watch-items carry-forward (to the next cycle)

- **Effective-permissions simulator (Q7)** — drive the built `SimulatePrincipalPolicy` wrapper;
  add Azure RBAC role-assignment evaluation. The defining CIEM-depth work.
- **Statement-level admin detection** — consume the Task-6 policy documents + inline-policy docs.
- **Patterns B + C** — re-evaluate per WI-I9 when a genuine multi-account / region-scoped
  consumer appears (triggers in the [WI-I8 doc](f-3-hoist-completion-2026-06-10.md)).
- **GCP IAM CIEM (Q4)**, **Conditional Access + PIM (Q3)**, **deep federation chains (Q5)**,
  **multi-account/tenant (Q6)** — all v0.3.

## §7. Out of scope (deferred to v0.3, locked)

GCP IAM CIEM · effective-permissions simulator + used-vs-granted · Azure Conditional Access +
PIM · deep cross-cloud federation chains · per-app workload identity federation · multi-account
/ multi-tenant · Pattern B/C hoists. No parked work touched (ADR-013, Hermes, Wazuh, Surface UI,
v2.0 graph); no cross-agent drift.

## §8. Cross-references

- [D.2 v0.2 brainstorm (#313)](../superpowers/brainstorms/2026-06-09-d-2-identity-v0-2-brainstorm.md) · [plan (#314)](../superpowers/plans/2026-06-10-d-2-identity-v0-2.md)
- [#266 hoist candidates](f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) · [WI-I8 hoist-completion](f-3-hoist-completion-2026-06-10.md)
- [WI-I7 cross-agent sweep](d-2-identity-v0-2-cross-agent-sweep-2026-06-10.md) · [per-cloud CIEM coverage](d-2-identity-v0-2-ciem-coverage-2026-06-10.md)
- Prior closures: [F.3 #267](f-3-cloud-posture-v0-2-verification-2026-06-08.md) · [D.5 #288](d-5-multi-cloud-posture-v0-2-verification-2026-06-09.md) · [D.1 #312](d-1-vulnerability-v0-2-verification-2026-06-09.md)

---

## D.2 Identity (CIEM) v0.2 — **CYCLE CLOSED** ✅

24/24 tasks · 7/7 milestones · the **first charter hoist** (3 of 5 #266 patterns) complete ·
multi-cloud CIEM at Level 2 (live AWS IAM + Azure AD + federation) · 5384 passed / 0 failed ·
substrate-seal discipline intact (RED only for the intentional hoists). Cycle 4 of the detection
track done.

— recorded 2026-06-10 (D.2 v0.2 Task 24; docs-only; cycle closure).
