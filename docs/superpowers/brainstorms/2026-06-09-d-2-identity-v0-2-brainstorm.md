# D.2 Identity (CIEM) v0.2 — brainstorm (live multi-cloud IAM + federation forensics + charter hoist) (2026-06-09)

> **Investigation only.** Fourth cycle on the strict-serial detection track (γ sequencing), after [F.3 v0.2 (#267)](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md), [D.5 v0.2 (#288)](../../_meta/d-5-multi-cloud-posture-v0-2-verification-2026-06-09.md), [D.1 v0.2 (#312)](../../_meta/d-1-vulnerability-v0-2-verification-2026-06-09.md). D.2 is multi-cloud **Identity / CIEM** — Wiz CIEM weight ~6–8 multi-cloud points. **This is the cycle where the [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) third-consumer charter hoist FINALLY fires** — the substrate-seal-empty streak (F.3 + D.5 + D.1) ends here, **intentionally, SAFETY-CRITICAL**. 13 axes + **7 Q-locks for operator review**. **No plan, no code, no charter touch.** Template mirrors the [D.1 brainstorm (#289)](2026-06-09-d-1-vulnerability-v0-2-brainstorm.md).

---

## §1. Axis 1 — Ground truth (D.2 Identity current state)

`packages/agents/identity/`, **v0.1.0**.

- **Deps** ([`pyproject.toml`](../../../packages/agents/identity/pyproject.toml)): `nexus-charter`, `nexus-shared`, `nexus-eval-framework`, **`boto3`/`botocore`** — **AWS-only**; **no `azure-*`, no `google-*`, no `cloud-posture`** (Azure AD + GCP are net-new).
- **OCSF:** emits **`class_uid 2004` — Detection Finding** (verified). **Not** 3001/2003 — a third distinct family from CSPM 2003 (F.3/D.5) and Vulnerability 2002 (D.1).
- **Tools** ([`tools/`](../../../packages/agents/identity/src/identity/tools/)): **`aws_iam.py`** (`aws_iam_list_identities` — boto3 users/roles/policies/groups, `asyncio.to_thread`, takes a `profile`), **`aws_access_analyzer.py`** (IAM Access Analyzer), **`permission_paths.py`** (privilege-path analysis). **142 tests.**
- **ADR-007 compliant** (agent + cli + eval_runner + normalizer + summarizer + nlah).
- **Load-bearing finding:** D.2 v0.1 **already has live-capable AWS IAM tooling** (raw boto3 with a `profile` arg) + Access Analyzer + permission paths — but **no `CredentialResolver` seam, no live-eval lane, no Azure/GCP**. So v0.2's AWS work is largely **adopting the hoisted charter `CredentialResolver` + a live lane + hardening**; Azure AD is net-new.

## §2. Axis 2 — Charter hoist scope (THE critical Q1)

Per [#266](../../_meta/f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md), F.3 established 5 in-package patterns, D.5 mirror-shaped (2nd consumer, no hoist), and **D.2 is the genuine 3rd consumer → the hoist fires now**. The five patterns + #266's ascending-effort order (D→E→C→A→B), each its **own SAFETY-CRITICAL PR**:

| Pattern                          | What                                                                   | Effort | Does D.2 genuinely consume it?                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **A — CredentialResolver**       | per-run cloud session from profile/default chain; no-secrets invariant | medium | **Yes** — the canonical trigger; AWS IAM (today raw boto3) + Azure Graph both need it                                                     |
| **D — live-eval lane gating**    | env-gate + skip-message + reachability shape                           | small  | **Yes** — D.2 needs `NEXUS_LIVE_IDENTITY_*` lanes                                                                                         |
| **E — partial-scan degradation** | degradation contract + degraded-marker shape                           | small  | **Yes** — per-identity/per-tenant degradation                                                                                             |
| **C — region scoping**           | precedence + `run()` signature                                         | small  | **No** — **identity is region-less** (IAM, Azure AD/Entra, GCP IAM are all global). D.2 is not a genuine region consumer.                 |
| **B — account autodiscovery**    | discover account/scope + regions                                       | large  | **Partial** — needs account/tenant _scope_ discovery, but this is the most cloud-divergent (account vs subscription vs tenant vs project) |

**Finding:** the clean cleavage is **A + D + E** — the three patterns D.2 actually consumes. **Pattern C should NOT hoist driven by D.2** (no region dimension → hoisting it here bakes an assumption D.2 never exercises; wait for a genuine region-scoped 3rd consumer). **Pattern B** (large, most-divergent) is best deferred until an account-model consumer forces it. → **Q1**.

## §3. Axis 3 — Live AWS IAM scope

v0.1 already ships `aws_iam_list_identities` (users/roles/policies/groups) + `aws_access_analyzer` + `permission_paths`. v0.2 = make them **live** through the hoisted `CredentialResolver` + a lane. Candidate additions: STS `GetCallerIdentity`, IAM Roles Anywhere, used-vs-granted (Axis 8). Per [benchmark §5](../../strategy/competitive-benchmark-2026-06-08.md), used-vs-granted + effective-permissions are the **L3 residual**. → Q2.

## §4. Axis 4 — Live Azure AD / Entra scope (net-new)

Net-new (no `azure-*` dep today). Microsoft **Graph** via `azure-identity` (`DefaultAzureCredential` — the same shape D.5 uses, reinforcing the 3rd-consumer hoist). Candidates: users, groups, **service principals**, **managed identities**, app-vs-delegated permissions; Conditional Access + PIM are deeper. → Q3.

## §5. Axis 5 — GCP IAM scope (or deferred?)

D.5 ships `rules_gcp/` — but those are **CSPM posture** CIS rules, **not CIEM entitlement** analysis (a different concern). Per [benchmark §5](../../strategy/competitive-benchmark-2026-06-08.md) GCP IAM (CIEM) is the **L3** lever; benchmark L2 is explicitly "live AWS IAM + Azure AD/Entra". → Q4 (recommend defer to v0.3).

## §6. Axis 6 — Federation forensics

Benchmark L2 includes "SAML/OIDC federation forensics". Surface: **trust relationships** (which IdPs a tenant trusts — Okta→AWS, Okta→Azure AD), AWS IAM Identity Center, Azure AD federation. Deep cross-cloud trust-chain _traversal_ is heavier. → Q5 (recommend basic detection at v0.2; deep chain → v0.3).

## §7. Axis 7 — Effective-permissions simulator

Wiz computes **effective permissions** (actual access after policy + condition evaluation) — computationally heavy (policy simulation). Per benchmark, the **L3 residual** for D.2. → Q7 (recommend out of scope at v0.2).

## §8. Axis 8 — Used-vs-granted permission analysis

High-value ("200 permissions granted, 12 used") but requires **CloudTrail / Azure Activity Log / GCP Audit Log** integration — a heavy data-plane dependency. Pairs with the effective-permissions simulator as a **v0.3** concern (audit-log-dependent). **Not a v0.2 Q-lock; documented as v0.3 non-scope.**

## §9. Axis 9 — OCSF emission (`class_uid 2004`)

D.2 emits **2004 (Detection Finding)** — verified. v0.2 keeps the wire shape invariant (analog F.3/D.5/D.1 byte-identity discipline); any new evidence field must be **additive** (the eval compares finding counts/severities). → WI-I5.

## §10. Axis 10 — Cross-agent OCSF 2004 consumer inventory

A **broad** consumer set (by `class_uid 2004` / `Detection Finding` reference): runtime-threat (5), investigation (4), threat-intel (4), network-threat (3), compliance (2), audit, cloud-posture, synthesis. No agent imports `nexus-identity` (consumption is at the OCSF-class level). The closure sweep (WI-I7) is the **largest yet** — and must also confirm F.3 + D.5 + D.1 are green **after the charter hoist**. → WI-I7.

## §11. Axis 11 — Live integration lane naming

Mirror D.5/D.1's per-cloud precedent: **`NEXUS_LIVE_IDENTITY_AWS` + `NEXUS_LIVE_IDENTITY_AZURE`** (+ `_GCP` only if Q4 brings GCP in). Alternatives: single `NEXUS_LIVE_IAM`; per-IdP. **Recommendation: per-cloud** — follows the established precedent + maps to the credential shapes. (Follows precedent, so **not** a standalone Q-lock; folded into the plan.)

## §12. Axis 12 — Multi-account / multi-tenant scope

Analog to D.5 Q6 (single-sub) + D.1 Q6 (single-registry). Recommend **single-account (AWS) / single-tenant (Azure) at v0.2**, multi-account/Organizations + multi-tenant → v0.3. → Q6.

## §13. Axis 13 — Substrate seal — the INTENTIONAL break

This is the cycle where the seal-empty streak **ends** — the hoists (Q1) touch `packages/charter/**`, which is **correct, planned, SAFETY-CRITICAL** (not a discipline break). Discipline still holds: **minimal, well-scoped, per-pattern PRs** (per #266: "each hoist is its own SAFETY-CRITICAL PR … not a batch"), **never a wholesale charter rewrite**. Under Q1=(B) that is **3 charter PRs** (A + D + E), each with a short hoist plan-doc + the WI-1 seal red **by design**. → Q1 + WI-I2.

---

## §14. Proposed Q-locks (operator decides — fresh-eyes review)

**Q1 — Charter hoist scope (THE critical, SAFETY-CRITICAL decision).**

- (A) Hoist **all 5** patterns (A–E) — ~5 SAFETY-CRITICAL PRs; but **C has no D.2 consumer** (identity is region-less) and **B is large/most-divergent**.
- **(B) Hoist A + D + E** — the three D.2 **genuinely consumes** as the 3rd consumer; **defer C** (region-less identity — no genuine consumer; hoisting bakes an unused assumption) and **B** (large divergence; hoist when an account-model consumer forces it). 3 SAFETY-CRITICAL PRs, ascending effort **E → D → A**.
- (C) Hoist **only A** (CredentialResolver) — minimal touch; D + E stay mirror-shape in-package this cycle.
- **Recommend (B).** It applies the third-consumer rule _precisely_ — hoist exactly what the 3rd consumer uses — while minimizing the SAFETY-CRITICAL surface. The genuine finding (identity has no region dimension) is why the #266 "D→E→**C**→A→B" order is trimmed to **E→D→A** here: C waits for a real region-scoped 3rd consumer. (Note: #266's option of leading with C/the small ones is suboptimal for D.2 because **A is the actual trigger** and **C is unused**.)

**Q2 — AWS IAM scope at v0.2.**

- **(A) Live users + roles + policies + groups + IAM Access Analyzer** · (B) without Access Analyzer (→ v0.3) · (C) minimal IAM read-only.
- **Recommend (A).** v0.1 **already ships** `aws_iam` + `aws_access_analyzer` + `permission_paths` (offline/raw-boto3); v0.2 makes them **live** via the hoisted resolver + a lane. Dropping Access Analyzer would _remove_ built capability — keep it.

**Q3 — Azure AD / Entra scope at v0.2.**

- (A) users + groups + SPs + managed identities + basic Conditional Access · **(B) users + groups + service principals + managed identities (no Conditional Access)** · (C) users + SPs only.
- **Recommend (B).** Net-new via Microsoft Graph (`DefaultAzureCredential`). Covers the CIEM core (incl. the SP + managed-identity surface attackers abuse); **Conditional Access + PIM defer to v0.3** (policy-evaluation depth pairs with the effective-permissions simulator).

**Q4 — GCP IAM (CIEM) at v0.2.**

- (A) in scope (full 3-cloud) · **(B) deferred to v0.3** · (C) extend D.5's GCP posture rules only.
- **Recommend (B).** Benchmark L2 is explicitly "AWS IAM + Azure AD/Entra"; GCP IAM (CIEM) is the **L3** lever. D.5's `rules_gcp` is CSPM **posture**, not CIEM **entitlement** — a different concern, not a v0.2 shortcut. Keeps the (already large) charter-hoist cycle bounded to 2 clouds.

**Q5 — Federation forensics depth at v0.2.**

- (A) SAML + OIDC trust-chain analysis (depth-first) · **(B) basic federation detection** (trust relationships: IAM Identity Center, AAD federation, trusted IdPs) · (C) out of scope (→ v0.3).
- **Recommend (B).** Federation is genuinely L2 (benchmark), but depth-first cross-cloud chain _traversal_ is heavy. v0.2 detects **which trust relationships exist**; deep chain analysis (Okta→AWS→assume-role paths) → v0.3.

**Q6 — Multi-account / multi-tenant at v0.2.**

- **(A) single-account (AWS) / single-tenant (Azure)** · (B) multi-account at v0.2.
- **Recommend (A).** Direct analog to D.5 Q6 + D.1 Q6. Multi-account/Organizations + multi-tenant → v0.3. Bounds the cycle.

**Q7 — Effective-permissions simulator at v0.2.**

- **(A) out of scope; explicit v0.3** · (B) basic read-only simulator at v0.2.
- **Recommend (A).** The documented Wiz **L3 residual**; pairs with used-vs-granted (Axis 8, audit-log-dependent). v0.2 stays at **granted-permissions** analysis.

---

## §15. Preemptive watch-items (from F.3 + D.5 + D.1 lessons)

- **WI-I1** — **per-cloud IAM coverage honesty:** AWS / Azure measured **separately**, each `[estimate]`-tagged, **no aggregate** (analog WI-D1 / WI-V1). If v0.2 lands ~30% CIEM not ~50%, say so plainly.
- **WI-I2** — **charter hoist surface minimal:** exactly the patterns Q1 selects, each a **separate SAFETY-CRITICAL PR** with a short hoist plan-doc; document each charter touch plainly; **no wholesale rewrite**.
- **WI-I3** — **honest L2 coverage** (analog WI-C / WI-D3 / WI-V3).
- **WI-I4** — **live end-to-end IAM scanning, not seams** — the D.1 WI-V6 standard: a CI-wired proof that runs credential → list → analyze → OCSF 2004, plus gated live lanes.
- **WI-I5** — **OCSF 2004 byte-identical eval cases per task.**
- **WI-I6** — **federation forensics depth honest** — what's deep vs surface stated plainly.
- **WI-I7** — **cross-agent regression sweep at closure** — the **largest yet**: F.3 + D.5 + D.1 + the 2004 consumers (runtime-threat, investigation, threat-intel, network-threat, compliance, audit, cloud-posture, synthesis) all green **after the charter hoist**. The hoist is the risk surface — this sweep is the proof it didn't regress the substrate.

## §16. Out of scope (locked discipline)

Parked per [macro plan §1.5](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md): ADR-013, Hermes, Wazuh, AppSec/AI-SPM, Surface UI, v2.0 graph. Also out: GCP IAM (Q4 → v0.3), effective-permissions simulator (Q7 → v0.3), used-vs-granted (Axis 8 → v0.3, audit-log-dependent), deep federation chains (Q5 → v0.3), multi-account/tenant (Q6 → v0.3), F.3/D.5/D.1 v0.3, #253 substrate, A.1 / D.7 work, plan-doc drafting, **any charter touch** (the hoist happens in execution per the Q1 outcome — not in this brainstorm).

## §17. Cross-references

- **[F.3 v0.2 hoist candidates (#266)](../../_meta/f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) — THE document this cycle consumes** (5 patterns, efforts, sequencing, the SAFETY-CRITICAL per-PR cadence).
- [F.3 v0.2 verification (#267)](../../_meta/f-3-cloud-posture-v0-2-verification-2026-06-08.md) · [D.5 v0.2 brainstorm (#268)](2026-06-09-d-5-multi-cloud-posture-v0-2-brainstorm.md) (2nd-consumer mirror-shape) · [D.5 v0.2 verification (#288)](../../_meta/d-5-multi-cloud-posture-v0-2-verification-2026-06-09.md)
- [D.1 v0.2 brainstorm (#289)](2026-06-09-d-1-vulnerability-v0-2-brainstorm.md) (the "different-shape → not a consumer" precedent) · [D.1 v0.2 verification (#312)](../../_meta/d-1-vulnerability-v0-2-verification-2026-06-09.md)
- [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (third-consumer rule — **now fires**) · [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
- [Macro plan §5](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) · [Competitive benchmark §5 (CIEM) + §3 weighting](../../strategy/competitive-benchmark-2026-06-08.md)

---

— recorded 2026-06-09 (D.2 Identity v0.2 brainstorm; investigation-only; 13 axes + 7 Q-locks; SAFETY-CRITICAL charter-hoist cycle; held for fresh-eyes operator Q-lock review).
