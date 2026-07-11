# Read-API Contract — foundation (v1, Vuln Mgmt pilot slice)

**Date:** 2026-07-08 · **Branch:** `feat/product-foundation` · **Stack:** FastAPI (read-API) · React+TS+Vite (frontend, later)

Contract-first: this defines the JSON the frontend binds to, **grounded in what the backend graph holds
today**. Every field is tagged: ✅ in the graph now · 🔧 small backend enrichment (leaf) · 🔗 from a shared
capability (posture rollup / remediation). Building to this contract means the frontend never binds to a
shape the backend can't deliver.

## Cross-cutting conventions

- **Tenant scoping (hard).** Every request carries tenant context from the auth token; the API scopes
  **every** query to that tenant (the `SemanticStore` calls already take `tenant_id`). No cross-tenant read.
- **Persona = a server-applied filter, never client.** A `?domain=` param selects the persona lens; the
  server maps it to finding/node types (`vuln` → `{cve_finding, sbom_package, eol}`) and **enforces** it
  (RBAC, not a UI toggle — fixes the premortem's ungated-access finding). Unknown/absent domain → the
  caller's default entitlement.
- **Envelope.** `{ "data": …, "meta": { "offset": int|null, "total": int|null, "tenant": str, "generated_at": iso } }`.
  Errors: `{ "error": { "code": str, "message": str } }` with real HTTP status. No silent stale data.
- **Pagination.** Offset-based (`?offset=&limit=`) on every list — the mock has none; real lists need it.
- **Auth/RBAC** sit behind an interface (`require_tenant()`, `require_entitlement(resource, action)`)
  that is **stubbed now** (single dev tenant, allow-all) and swapped for a real IdP later — callers don't change.

---

## Pilot endpoints (the first slice)

### 1. `GET /v1/inventory/cloud-resources` → the `cloud-resources` page (🟢 pilot, frontend-only)

Query: `?offset=&limit=&kind=&public=`. One row per `CLOUD_RESOURCE` node for the tenant.

```jsonc
{ "data": [ {
  "id": "arn:aws:ecs:…:svc/web",   // ✅ external_id
  "kind": "ecs-service",            // ✅ property (ecs-service|container-image|azure-container-group|gcp-cloud-run-service|…)
  "cloud": "aws",                   // 🔧 derive from ARN/kind prefix (trivial, in the API)
  "is_public": true,                // ✅ property
  "region": "us-east-1"             // 🔧 present for some writers; null when absent — declare optional
} ], "meta": { … } }
```

### 2. `GET /v1/findings/vulnerabilities` → the `vulnerabilities` list (🟡, frontend + filter)

Query: `?offset=&limit=&severity=&kev=&domain=vuln`. Each `CVE_FINDING` joined to its resource via `VULNERABLE_TO`.

```jsonc
{ "data": [ {
  "cve_id": "CVE-2024-1234",        // ✅ external_id
  "severity": "critical",           // ✅ property
  "kev": true,                      // ✅ property
  "epss": 0.94,                     // ✅ property (epss_score; optional)
  "resource": "arn:…/web",          // ✅ VULNERABLE_TO src entity_id
  "component": "openssl@1.1.1",     // 🔧 in Trivy raw (PkgName/Version) — stamp onto the edge/node (leaf)
  "fix_version": "1.1.1w",          // 🔧 in Trivy raw (FixedVersion) — stamp (leaf)
  "status": "open"                  // 🔧 no status model yet → default "open" until a triage store exists
} ], "meta": { … } }
```

### 3. `GET /v1/findings/vulnerabilities/{cve_id}` → the detail panel (🟡, the enrichment leaf)

```jsonc
{
  "data": {
    "cve_id": "CVE-2024-1234",
    "severity": "critical",
    "kev": true,
    "epss": 0.94,
    "cvss_v3_score": 9.8, // 🔧 model has cvss_v3_score but node doesn't stamp it — stamp (leaf)
    "cwe": ["CWE-79"], // 🔧 Trivy raw CweIDs — stamp (leaf)
    "description": "…", // 🔧 Trivy raw Description — stamp or fetch (leaf)
    "fix_version": "1.1.1w", // 🔧 (leaf)
    "affected_resources": ["arn:…/web", "arn:…/api"], // ✅ all VULNERABLE_TO src for this cve
    "first_seen": "2026-07-01T…", // ✅ entity created_at
    "remediation": { "tier": "advisory", "advice": "…" }, // 🔗 Remediation chapter (FixAdvice, advisory tier)
  },
}
```

### 4. `GET /v1/posture?domain=vuln` → binds `overview` + `inventory-overview` (🟡→ backend done via PR #810)

Serves the **posture rollup** (`posture.json`) filtered to the domain. 🔗 shared capability — already built.

```jsonc
{ "data": {
  "coverage": { "domain_pct": 57, "collector_pct": 89, "surfaced_pct": 31 },      // 🔗 posture rollup
  "severity_distribution": { "critical": 12, "high": 40, "medium": 88, "low": 210 },// 🔗 (filter to vuln domain)
  "by_domain": [ { "domain":"vulnerability","critical":12,"high":40,… } ],          // 🔗
  "inventory_counts": { "cloud_resource": 2841, "cve_finding": 350, "sbom_package": 9120 }, // 🔗
  "exposure_funnel": { "exposed": 40, "vulnerable": 22, "kev": 6, "exploitable": 3 },// 🔗
  "trends": [ { "at":"…","attack_paths":24,"critical":12,"high":40 } ]              // 🔗 (empty until scan 2)
} }
```

---

## What this contract surfaces (contract-first payoff)

- The `cloud-resources` **pilot is pure frontend** — every field is ✅ today.
- The `vulnerabilities` **list is frontend + a trivial API derive** (`cloud` from ARN); the **detail panel is
  the one real leaf**: stamp `component / fix_version / cvss / cwe / description` from the Trivy raw the
  agent already parses onto the CVE node (small, bounded, offline — a `vulnerability` producer edit + test).
- `overview` / `inventory-overview` **bind the posture rollup** (already built) — no new backend.
- `status` (triage) has no backend → default `"open"` until a triage store exists (a small later leaf, or a chapter if it grows to workflow).

## Next steps (on this contract)

1. Scaffold the FastAPI app (`apps/api` or `services/read-api`): the envelope, `require_tenant`/`require_entitlement`
   stubs, and endpoint **1** (`cloud-resources`) reading `SemanticStore.list_entities_by_type`, with a test
   against an in-memory fixture graph (proves the contract end-to-end against real backend code).
2. Endpoint **4** (`posture`) — thin serve of the rollup output.
3. Endpoints **2/3** (`vulnerabilities` list + detail) — includes the Trivy-enrichment leaf for the detail fields.
4. Then the React+TS+Vite skeleton binds endpoint 1 → the `cloud-resources` pilot page renders **real data**.
