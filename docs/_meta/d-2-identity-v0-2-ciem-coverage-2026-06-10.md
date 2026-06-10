# D.2 Identity v0.2 — per-cloud CIEM coverage `[estimate]` notes (2026-06-10)

> **D.2 v0.2 Milestone 7, Task 22.** Measures **AWS IAM** and **Azure AD / Entra** CIEM
> coverage **separately** per **WI-I1** — there is **no aggregate "multi-cloud CIEM"
> number, no averaging, no comparison between the two clouds**. Every figure is an
> `[estimate]`, not an instrumented ratio, and is reported low/honest per **WI-I3**.

## §0. The honest headline

The v0.2 story is **breadth, not depth**. v0.1 was **AWS-IAM-only** (benchmark: ~30%,
"built-but-unused simulator path"). v0.2 adds **live Azure AD/Entra + basic SAML/OIDC
federation** — a genuine multi-cloud milestone — but the **defining CIEM capability,
computed effective permissions across entitlement chains, is NOT in v0.2.** It stays
the L3 residual (Q7). So v0.2 CIEM = **entitlement inventory + heuristic over-privilege
detection + federation trust detection**, per cloud — not "true" effective-access CIEM.

## §1. Methodology

- **Baseline ("complete CIEM" per cloud):** effective-access evaluation across the
  identity graph (what each principal can _actually_ do, after policy + condition +
  boundary evaluation, across cross-resource entitlement chains) — the
  [benchmark §3.3](../strategy/competitive-benchmark-2026-06-08.md) definition. No
  enumerable in-repo denominator → the baseline is the qualitative target.
- **Why `[estimate]`:** the counts (detection types, enumerated resource classes) are
  exact; the _percentage_ is a judgement, reported as a low range, not rounded up.

## §2. AWS IAM CIEM — coverage `[estimate]` (measured alone)

**Covered at v0.2:** live enumeration (users / roles / groups / customer-managed
policy _documents_) via the hoisted `CredentialResolver`; 5 detection types —
over-privilege (admin-policy heuristic), dormant, external-access (Access Analyzer),
MFA-gap, federation (SAML + OIDC IdP trusts); Pattern-E partial-scan resilience; OCSF
2004 emission; the WI-I4 live end-to-end pipeline.

**NOT covered (→ v0.3):** the **effective-permissions simulator** (per-principal
`SimulatePrincipalPolicy` — built + tested, but not driven); used-vs-granted;
statement-level admin detection over the enumerated policy documents; IAM `Condition` /
SCP / permission-boundary evaluation; multi-account / Organizations.

| Axis                                  |      v0.1 |                                 v0.2 | Delta                                             |
| ------------------------------------- | --------: | -----------------------------------: | ------------------------------------------------- |
| Live IAM enumeration                  | inventory |     inventory **+ policy documents** | + policies dimension                              |
| Detection types                       |         4 |                 **5** (+ federation) | + federation                                      |
| Effective permissions (the CIEM core) |      none | **none** (simulator built, undriven) | unchanged — v0.3                                  |
| **AWS IAM CIEM `[estimate]`**         |  **~30%** |                          **~35–40%** | modest depth gain; mostly resilience + federation |

**No inflation (WI-I3):** the jump is small because the heavy part (effective
permissions) is deferred. v0.2's AWS value is **federation detection + Pattern-E
resilience + the live e2e pipeline**, not a CIEM-depth leap.

## §3. Azure AD / Entra CIEM — coverage `[estimate]` (measured alone)

**Covered at v0.2:** live Microsoft Graph enumeration — users + groups + **service
principals + managed identities** (the SP/MI surface attackers abuse) + federation
(federated domains + tenant OIDC IdPs); Pattern-E partial-scan resilience; the same
OCSF 2004 wire shape (measured **separately**, never merged with AWS).

**NOT covered (→ v0.3):** any **effective-permissions** evaluation (no Azure RBAC
role-assignment graph yet); **Conditional Access + PIM**; per-app **workload identity
federation** (`federatedIdentityCredentials`); no Access-Analyzer-equivalent
external-exposure surface; multi-tenant.

| Axis                               |     v0.1 |                                    v0.2 | Delta                                   |
| ---------------------------------- | -------: | --------------------------------------: | --------------------------------------- |
| Azure AD presence                  | **none** | users + groups + SPs + MIs + federation | **net-new**                             |
| Effective permissions (Azure RBAC) |     none |                                **none** | v0.3                                    |
| **Azure AD CIEM `[estimate]`**     |   **0%** |                             **~20–25%** | net-new identity inventory + federation |

**No inflation (WI-I3):** ~20–25% is **identity + federation inventory** — Azure RBAC
effective-permissions, the bulk of Azure CIEM depth, is entirely v0.3. The v0.2 value
is **establishing live Azure AD detection from zero**, not depth.

## §4. Verdict

- **AWS IAM CIEM: ~35–40% `[estimate]`** — inventory + 5 detection types + federation +
  resilience; effective-permissions simulator deferred (Q7 → v0.3).
- **Azure AD CIEM: ~20–25% `[estimate]`** — net-new identity + SP/MI + federation
  inventory; Azure RBAC effective-permissions + Conditional Access deferred (→ v0.3).
- **No aggregate** (WI-I1). The two numbers are not averaged or summed.

The cycle's CIEM contribution is **multi-cloud breadth + federation forensics**, with
**computed effective permissions honestly held for v0.3** — the single largest
remaining gap, exactly as the [benchmark](../strategy/competitive-benchmark-2026-06-08.md)
calls out.

---

— recorded 2026-06-10 (D.2 v0.2 Task 22; per-cloud `[estimate]`s, honest per WI-I3, no aggregate per WI-I1; docs-only).
