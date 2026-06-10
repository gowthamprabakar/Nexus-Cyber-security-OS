# F.3 charter-hoist completion (#266) — WI-I8 (2026-06-10)

> **D.2 Identity v0.2 Milestone 7, Task 23.** Records which of the five F.3 in-package
> patterns from [#266](f-3-cloud-posture-v0-2-hoist-candidates-2026-06-08.md) landed in
> `nexus-charter` during the D.2 cycle (the ADR-007 third-consumer hoist), which were
> deferred, and **why** — plus the trigger criteria for future hoists (WI-I8 / WI-I9).

## §0. Headline

The substrate-seal-empty streak (F.3 + D.5 + D.1 = 3 cycles) **ended here, intentionally
and minimally**: **3 of the 5 #266 patterns hoisted** — Patterns **E + D + A**, each its
own SAFETY-CRITICAL PR (Tasks 2–4) — and **2 deferred** (B + C), each for a concrete
reason. D.2 Identity was the genuine ADR-007 **third consumer** that fired the hoist.

## §1. Hoisted (3) — landed in `charter`, adopted fleet-wide

| #266 Pattern                     | Charter module                                                   | Task / PR     | Adopters                                                                     |
| -------------------------------- | ---------------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------- |
| **E — Partial-scan degradation** | `charter.degradation` (`sanitize_scan_error`, `degraded_marker`) | Task 2 (#343) | F.3 (origin), D.1; D.2 IAM + Azure consume it                                |
| **D — Live-eval lane gating**    | `charter.live_lane` (`nexus_live_enabled`, `live_skip_reason`)   | Task 3 (#344) | F.3, D.1 (3 registry lanes); D.2 IAM + Azure lanes consume it                |
| **A — CredentialResolver**       | `charter.credentials.CredentialResolver` (stateless ABC)         | Task 4 (#345) | F.3 (boto3), D.5 (Azure + GCP); D.2 AWS (Task 5) + Azure (Task 9) consume it |

Each adoption was byte-identical (no behavior change); the cross-agent regression sweep
([Task 20](d-2-identity-v0-2-cross-agent-sweep-2026-06-10.md)) proved no consumer broke.

### Deviation from #266's proposed paths (flat namespace)

#266 proposed nested charter paths (`charter/cloud/credentials.py`,
`charter/testing/live_lanes.py`, a `BaseAgent` contract). The cycle landed them in a
**flat charter namespace** instead — `charter/degradation.py`, `charter/live_lane.py`,
`charter/credentials.py` — matching the existing charter module layout
(`audit.py`, `budget.py`, `context.py`, …). The _contracts_ are exactly as #266
specified; only the file location is flatter. No `BaseAgent` base class was introduced
(Pattern A is a thin ABC each agent subclasses, not a god-object base).

## §2. Deferred (2) — and why

### Pattern B — Account + region autodiscovery → **deferred (no genuine consumer yet)**

D.2 is **single-account (AWS) / single-tenant (Azure)** per Q6 — it does not discover an
account universe or a subscription/region list. Pattern B is also the **largest +
most divergent** of the five (the _scope model_ differs per cloud: AWS Organizations vs
Azure subscriptions vs GCP projects), so hoisting it on a non-consumer would over-fit.
**Trigger for a future hoist:** the first agent that genuinely enumerates a multi-account
/ multi-subscription scope (an Organizations-aware cycle). Until then it stays in F.3.

### Pattern C — Region scoping (precedence + `run()` signature) → **dropped for identity (region-less)**

Identity is **region-less**: AWS IAM is a _global_ service (boto3 only needs an arbitrary
region for client construction, never a multi-region scan), and Azure AD / Graph is
_tenant-global_. So D.2 has **no region-scoping need** and is **not** a Pattern-C
consumer at all. Pattern C therefore did not fire here. **Trigger for a future hoist:** a
genuine region-scoped _third_ consumer alongside F.3 + D.5 (e.g. a new regional-resource
posture agent). Until then it stays in F.3.

## §3. Non-hoist items (stay per-agent — ADR-007 §4)

The cloud-specific bodies remain in each agent by design (WI-I2): boto3 / azure-identity /
google-auth session construction, per-cloud SDK clients, per-cloud error taxonomies +
retry policies, identifier naming (`profile` vs `source`), and the per-cloud reachability
probes. Only the cloud-agnostic _contracts_ hoisted.

## §4. Trigger criteria going forward (WI-I9)

The substrate-seal-empty discipline **resumes**. Each future cycle re-evaluates whether a
**new** hoist is genuinely needed:

1. A pattern hoists only when a **genuine third consumer** appears (ADR-007) — not on
   speculation, not on a mirror-shape second consumer.
2. **B** waits for a real multi-account / multi-tenant scope consumer.
3. **C** waits for a real region-scoped third consumer.
4. Any new hoist is its **own SAFETY-CRITICAL PR**, minimal surface (WI-I2), with a
   cross-agent regression sweep proving no consumer regressed.

## §5. Verdict

**#266 hoist status after D.2 v0.2: 3 hoisted (E + D + A), 2 deferred (B + C), with
documented triggers.** The first charter hoist is complete; the seal-empty streak
resumes for the next cycle.

---

— recorded 2026-06-10 (D.2 v0.2 Task 23, WI-I8; docs-only).
