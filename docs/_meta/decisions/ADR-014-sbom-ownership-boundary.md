# ADR-014: SBOM ownership boundary (AppSec build-time; D.1 deploy-time)

**Status:** ACCEPTED (2026-06-15)
**Author:** Operator (codified at B-1 launch)
**Supersedes:** None
**Related:** ADR-015 (secrets-in-runtime ownership), ADR-007 (agent reference model)
**References:**

- Q-AppSec-1 operator decision (`docs/_meta/q-appsec-2026-06-14.md`)
- D.1 Vulnerability v0.2 (registry/image/host SCA)

## Context

Both the new AppSec agent (D.14) and the Vulnerability agent (D.1) can produce a
Software Bill of Materials (SBOM) and run Software Composition Analysis (SCA).
Without an explicit boundary the two agents would double-scan dependencies and
emit overlapping findings — the same ambiguity ADR-015 resolved for secrets.

The natural seam is **where the artifact comes from**:

- **Build-time** — source repositories + CI (lockfiles, manifests in a checked-out
  repo). This is AppSec's native surface (it already authenticates to SCM).
- **Deploy-time** — container images, registries, running hosts. This is D.1's
  native surface (it already runs Trivy against images/registries/host rootfs).

## Decision

**SBOM/SCA ownership splits by artifact provenance:**

- **AppSec (D.14) owns build-time SBOM/SCA** — dependencies discovered by scanning
  source repositories and CI manifests/lockfiles.
- **D.1 (Vulnerability) owns deploy-time SBOM/SCA** — dependencies discovered by
  scanning images, registries, and hosts (its existing Trivy surface; unchanged).
- **No overlap.** AppSec does NOT scan images/registries/hosts; D.1 does NOT
  authenticate to SCM or scan source repos.
- A **shared SBOM-node shape** lets both agents contribute to the same dependency
  graph (build-time and deploy-time views of the same component) — the concrete
  shared schema is deferred (see Implementation gating); v0.1 keeps each agent's
  emission agent-local and additive.

## Rationale

1. **Provenance correctness.** Build-time and deploy-time SBOMs answer different
   questions (what the source declares vs. what the artifact ships). Splitting by
   provenance is the honest, non-overlapping cut.
2. **Reuses existing auth surfaces.** AppSec already holds SCM credentials
   (Pattern-A); D.1 already holds cloud/registry credentials. Neither needs the
   other's auth substrate.
3. **Mirrors the established agent-boundary pattern** (ADR-015 secrets; ADR-007
   reference model) — ownership by native surface, coordination by shared shape.

## Consequences

**Positive:**

- D.1 is unchanged by this ADR (no regression; deploy-time SCA stays as shipped).
- AppSec build-time SBOM/SCA is net-new capability with a clear, non-overlapping charter.
- Coverage attribution is unambiguous: build-time deps → AppSec; deploy-time deps → D.1.

**Negative / mitigated:**

- A component present at both build and deploy time appears in both agents' views.
  That is intentional (two provenances); de-duplication into a single dependency
  graph is a shared-schema concern, deferred below — not a double-count of risk
  because each view is provenance-tagged.

**Out of scope for B-1 / v0.3:**

- The concrete shared SBOM-node schema + cross-agent dependency-graph merge.
- AppSec SBOM emission itself (B-1 PR1 ships substrate + SCM + repo discovery;
  SCA/SBOM + IaC/SAST/secrets scanners land in subsequent B-1 PRs).

## Implementation gating

- **B-1 PR1** (this cycle): codify this ADR + scaffold D.14 (charter agent + SCM
  Pattern-A credential resolver + repo discovery). No SBOM emission yet.
- **B-1 PR2+**: build-time SCA/SBOM + IaC (Checkov, Q-AppSec-3) + secrets-in-code
  (gitleaks, Q-AppSec-4; routes to DSPM per ADR-015) + SAST (Semgrep, Q-AppSec-5).
- **v0.3+**: shared SBOM-node schema + D.1 cross-read (gated on schema consensus).
