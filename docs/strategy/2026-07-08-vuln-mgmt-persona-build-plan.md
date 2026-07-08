# Vulnerability Mgmt — Persona Build Plan (beachhead)

**Date:** 2026-07-08 · **Method:** full-stack (premortem-corrected) scoring · first real persona

## The architecture that makes this tractable

**Capabilities are platform-scoped; personas are bounded lenses over them.** You build a capability
(detection graph, remediation engine, aggregation, audit chain) **once**, platform-wide, and each
persona is a **filter + view** over it — never a persona-specific engine.

- Detection = one finding graph. Vuln sees `finding_type ∈ {CVE, SBOM_PACKAGE, EOL}`; Identity sees
  `{excessive-access, secret}`. Same graph, different `WHERE`.
- Remediation = one engine (one contract store, one executor, one audit chain). Vuln's Cure queue is
  `remediations WHERE domain = vuln`; Container's is `WHERE domain = k8s`. Same engine, different `WHERE`.

**You scope the query into a chapter, never the chapter itself.** The persona filter is a cheap
`where`-clause; the weight lives in the shared platform capability. This is why a persona slice is thin.

## Two layers of work

- **Layer A — Platform (shared, built once, persona-agnostic).** The foundation + the chapters. The
  Vuln slice _depends_ on these but does **not** build them. Building them lights up the relevant page
  in _every_ persona at once.
- **Layer B — The Vuln Mgmt slice (persona-scoped, thin).** A `domain = vuln` filter + a real frontend
  per page. This is what "building the Vuln Mgmt persona" actually is.

---

## Layer A — Platform prerequisites

### A0. Foundation (step 0, once, before any persona)

There is no frontend app and no API in the repo today. This is the hard gate:

1. **Frontend stack + app skeleton** (a real SPA project — the mock is a throwaway design).
2. **Read API** over the graph + `posture.json` (the mock has zero data-fetching; nothing can bind
   without this). Contract-first: define the response shapes the pages consume.
3. **Auth + RBAC shell** — sign-in, tenant context, and a real entitlement gate (the mock's persona
   picker "never gates access"; the premortem found ungated paths to destructive actions).

### A-chapters (own programs; the Vuln slice only _surfaces_ them at today's capability)

- **Remediation engine** — safety-critical, K8s-executor-only today; cloud execution + the
  contract/approval/rollback/signing state machine + RBAC are its own scope. **Vuln surface today:**
  the **advisory tier** (`FixAdvice` exists for every archetype) + K8s execution, filtered to
  `domain = vuln`. Cloud-execute is marked "depends on: Remediation chapter."
- **Patch producer** — no patch-lifecycle producer today. **Vuln surface today:** "**available
  fixes**" derived from CVE `fix_version` (already in the graph — a leaf). Full patch-state/deployment
  tracking is "depends on: Patch chapter."

---

## Layer B — The Vuln Mgmt slice (13 pages)

For each page: the platform capability it projects, the `vuln` filter, and the leaf work done _in the slice_.

| Page               | Bucket | Platform capability projected                   | Vuln filter                      | Leaf work in the slice                                                            |
| ------------------ | ------ | ----------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------------- |
| cloud-resources    | 🟢     | Cloud inventory (ARN spine)                     | vuln-relevant assets             | **frontend only** (schema real) → **PILOT**                                       |
| inventory-overview | 🟡     | Aggregation (posture rollup, PR #810)           | vuln inventory_counts            | frontend only (bind posture.json)                                                 |
| vulnerabilities    | 🟡     | Detection graph — CVE findings (Trivy/KEV/EPSS) | `finding_type=CVE`               | frontend + **detail-panel binding** (EPSS/CVSS/KEV/CWE/fix — data in CVE nodes)   |
| sbom               | 🟡     | SBOM graph (SBOM_PACKAGE)                       | image/host packages              | frontend + real package schema                                                    |
| container-images   | 🟡     | Image inventory (ECR/ACR/GCR)                   | container images                 | frontend + real image schema                                                      |
| audit              | 🟡     | Audit chain (F.6)                               | (shared; optionally vuln-scoped) | frontend + **paginated retrieval/verify API** (shared)                            |
| eol                | 🟡     | _(bounded producer)_ end-of-life                | packages past EOL                | **small producer** (SBOM ↔ EOL dataset) + frontend                                |
| vuln-catalog       | 🟡     | CVE catalog (NVD/KEV/EPSS ingested)             | all CVEs                         | **materialize catalog** view + frontend                                           |
| overview           | 🔴     | Aggregation + attack paths                      | vuln-domain aggregates           | frontend board + **light vuln KPIs** (KEV exposure, MTTP, top exploited)          |
| patch              | 🔴     | **Patch chapter**                               | vuln fixes                       | **descope → available-fixes** (leaf from `fix_version`); full lifecycle = chapter |
| cure-recommend     | 🔴     | **Remediation chapter**                         | `domain=vuln`, advisory          | **descope → advisory view** (filtered) over shared engine                         |
| cure-dryrun        | 🔴     | **Remediation chapter**                         | `domain=vuln`                    | descope → K8s dry-run where applicable; else "depends on chapter"                 |
| cure-execute       | 🔴     | **Remediation chapter**                         | `domain=vuln`                    | descope → K8s execute; cloud-execute "depends on chapter"                         |

**9 leaf pages** are fully buildable in the slice. **2 chapters** (Remediation, Patch) are surfaced at
today's capability via a filter, with an explicit "depends on" marker for the deferred depth.

---

## Sequence

1. **A0 Foundation** (platform): app skeleton + read API + auth/RBAC. _(Nothing is real until this exists.)_
2. **Pilot — `cloud-resources`** (🟢, frontend-only): prove the whole pattern end-to-end (stack → API →
   binding → states → auth gate) on the cheapest page before any backend push.
3. **Leaf pages** (contract → bounded backend if needed → frontend + states), value-ordered:
   `vulnerabilities` → `inventory-overview` → `overview` → `sbom` → `container-images` → `vuln-catalog`
   → `eol` → `audit`.
4. **Surface the chapters at current capability** (filtered views, not new engines): Cure at advisory +
   K8s (`domain=vuln`); patch as available-fixes. Mark deferred depth "depends on: Remediation / Patch
   chapter."
5. **Persona done** = the vuln lens is real end-to-end; the chapters deepen later as their own programs,
   and every persona's view of them lights up together.

## The discipline (so a slice never balloons)

When a page hits a gap, classify its root: **producer exists → leaf (frontend/wiring); needs one bounded
offline producer → leaf (small backend); needs a core capability that's a program (execution, live-cloud,
a state machine, safety-critical) → CHAPTER.** Slices contain only leaf work. Chapters are horizontal —
you descope the page to what the chapter delivers today and build the chapter separately, once, for
everyone.
