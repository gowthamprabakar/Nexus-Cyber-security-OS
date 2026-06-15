# ADR-015: Secrets-in-runtime ownership boundary (D.1 scans; DSPM emits OCSF 2003)

**Status:** ACCEPTED (2026-06-15)
**Author:** Operator
**Supersedes:** None
**Related:** ADR-014 (SBOM ownership boundary, D.1 vs AppSec)
**References:**

- Q-A-2 Fork B operator decision (2026-06-14)
- `docs/_meta/v0-3-a-2-4-recon-2026-06-14.md`
- `docs/_meta/v0-3-track-a-baseline-reconciliation-2026-06-14.md`

## Context

The vulnerability agent (D.1) is technically capable of detecting secrets in
process memory and container scans (via Trivy's built-in secret scanner, which
Trivy already ships). However, runtime secrets are sensitive-data exposures —
semantically NOT vulnerabilities in the OCSF 2002 sense (which requires
CVE-shaped findings via FINDING_ID_RE).

Two ownership questions arise:

1. Should D.1 emit secrets-in-runtime findings as OCSF 2002 (vuln class)?
2. Or route to DSPM (data-security agent) for OCSF 2003 emission?

Q-A-2 Fork B (operator decision, 2026-06-14) chose route-to-DSPM. The A-2.4
recon (2026-06-15) confirmed Trivy's normalizer currently DROPS secrets silently
(no CVE-ID), and identified the additive OCSF-2003 discriminator + sibling-
workspace transport as the implementation path.

## Decision

**Secrets-in-runtime detection is owned across two agents with explicit roles:**

- **D.1 vulnerability SCANS.** Trivy's built-in secret scanner (already shipping,
  Apache-2.0) detects secrets in process memory + container layers during D.1's
  existing scan runs. D.1 writes raw secret hits to its OWN findings workspace
  (the existing sibling-workspace pattern).

- **DSPM (data-security) EMITS.** DSPM reads D.1's sibling workspace, recognizes
  secret hits via the OCSF 2003 Data Security Finding discriminator (additive
  `DataSecurityFindingType.SECRET_EXPOSED_IN_RUNTIME`), and emits the OCSF 2003
  finding into the canonical findings stream.

- **D.1 does NOT emit OCSF 2002 Vulnerability Findings for secrets.** The OCSF
  type mismatch is explicit: a secret in runtime is a sensitive-data exposure,
  not a vulnerability.

- **No new bus, no new substrate.** The sibling-workspace read pattern is the
  established cross-agent transport in v0.3; ADR-014 codified a parallel pattern
  for SBOM ownership (AppSec writes; D.1 contributes).

## Rationale

Three architectural alignments:

1. **OCSF type correctness.** OCSF 2002 has FINDING_ID_RE that's CVE-shaped;
   secrets have no CVE. OCSF 2003 is the right class.

2. **Agent ownership correctness.** D.1 is the SCANNER; DSPM owns sensitive-
   data-class emission. This mirrors ADR-014's SBOM boundary.

3. **Future-proofing for AppSec secrets-in-code (Track B).** Q-AppSec-4 will
   cover secrets-in-CODE (CI/CD-derived gitleaks scans). Per ADR-015, BOTH
   secrets variants (in-code from AppSec; in-runtime from D.1) route to DSPM
   for unified OCSF 2003 emission. DSPM becomes the single emission point.

## Consequences

**Positive:**

- D.1 reuses existing Trivy infrastructure (FLAG-3: target expansion, not new engine).
- DSPM owns the OCSF 2003 emission contract cleanly.
- Cross-agent coordination via existing sibling-workspace transport (no new
  substrate; pause triggers #19/#29 CLEAR).
- AppSec secrets-in-code (future Q-AppSec-4) integrates without re-architecture.

**Negative / mitigated:**

- D.1's coverage doc must note that secrets-in-runtime contributes to DSPM's
  weighted coverage, not D.1's (avoids double-counting; aligns with baseline
  reconciliation at #670).
- Cross-agent timing: DSPM must read D.1's sibling-workspace AFTER D.1's scan
  completes within a tenant scan window (acceptable; existing pattern).

**Out of scope for v0.3:**

- AppSec secrets-in-code routing to DSPM (Track B B-2 work).
- DSPM emission throttling/dedup across cross-agent contributors (v0.4).

## Implementation gating

A-2.4 implementation cascade UNBLOCKED by this ADR. The recon already resolved
three forks:

- Fork 1: (1a) New `DataSecurityFindingType.SECRET_EXPOSED_IN_RUNTIME` discriminator
- Fork 2: (2a) Sibling-workspace transport (P1)
- Fork 3: (3a) Reuse Trivy's built-in secret scanner

Self-merge cascade may proceed after this ADR lands on main.
