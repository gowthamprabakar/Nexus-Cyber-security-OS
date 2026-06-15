# D.14 AppSec v0.3 (B-1) — Coverage

**Date:** 2026-06-15 · Measured **per-scanner-family**, no aggregate · all figures `[estimate]`.

D.14 is a **net-new agent** introduced in cycle B-1 — it was not in the #647 baseline,
so it adds a **new build-time detection surface** rather than re-rating an existing one.

## Covered at v0.3 (B-1)

- **IaC misconfiguration (Checkov)** — Terraform/CloudFormation/K8s/etc. `failed_checks`
  → OCSF 2003 (`appsec_iac_misconfiguration`), `compliance.control` = `CKV_*` id.
- **SAST (Semgrep OSS)** — `results[]` → OCSF 2003 (`appsec_sast_finding`); carries
  check_id + message + file:line (not the matched snippet). Default `p/ci` ruleset; OSS
  CLI only (LGPL-2.1), Pro registry never targeted (#23).
- **Secrets-in-code (gitleaks)** — redacted → `code_secrets.json` handoff → **DSPM emits
  OCSF 2003** `SECRET_EXPOSED_IN_CODE` (ADR-015; plaintext never crosses).
- **SCM discovery + checkout** — GitHub / GitLab / Bitbucket connectors (httpx,
  Pattern-A auth) + shallow clone-for-scan.

## NOT covered (→ v0.4 / later B-cycles)

- **DAST / runtime app testing** — out of build-time scope.
- **Dependency/SBOM vuln scanning** — D.1 owns deploy-time SBOM (ADR-014); AppSec
  build-time SBOM emission is a later B-cycle.
- **License/policy compliance scanning, custom org rulesets** — not built.
- **Live SCM lift is not realized by wiring alone** — the connectors + clone path are
  gated/operator-run; coverage is realized when an operator points them at real repos
  (mirrors the A-1 live-loop caveat #661 / baseline reconciliation #670 caveat 4).

## Honest estimate

**New surface, not a re-rated baseline.** D.14 covers the three mainstream build-time
AppSec families (IaC + SAST + secrets) at breadth-not-depth: one mature OSS engine per
family, default rulesets, no custom-rule authoring. Bounded judgement, not a benchmark.
Per ADR-015 + baseline reconciliation #670, **secrets-in-code coverage attributes to
DSPM** (single OCSF 2003 emission point), not double-counted under AppSec.
