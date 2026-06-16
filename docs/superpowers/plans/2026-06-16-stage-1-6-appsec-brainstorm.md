# v0.4 Stage 1.6 (Track B) — D.14 AppSec B-2/B-3/B-4 + SCM repo inventory — brainstorm

**Status:** brainstorm for operator review (per-PR review). Template locked at #712 + §9/§10.
**Directive:** `v0-4-directive-2026-06-16.md` §3 Stage 1.6 + Option X. **Catalogue:** #711 "D.9 AppSec" (status WRONG — see R-2).
**Agent:** `packages/agents/appsec` (D.14, built v0.3 B-1). **Discipline:** depth-first; **per-PR review (continues D.14 discipline)**; seal EMPTY; live gated.

> ⚠️ R-2: catalogue marks "D.9 AppSec — Unbuilt"; reality = **D.14, built v0.1 in v0.3 B-1** (#690-707). v1.1 catalogue amendment fixes status + number.

## 1. Current state (recon vs main `fec57f8`)

| Capability     | State                                                                                                     | Evidence                                                   |
| -------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Scanners       | Checkov IaC + gitleaks secrets + Semgrep SAST (default community pack)                                    | `tools/{checkov,gitleaks,semgrep}_runner.py` + normalizers |
| SCM connectors | GitHub + GitLab + Bitbucket (Pattern-A; offline `StaticScmConnector`)                                     | `tools/{github,gitlab,bitbucket}_connector.py`             |
| Multi-tenant   | **none** — per-tenant cred store NOT impl (raises; **SAFETY-CRITICAL substrate debt**)                    | `credentials.py:59-65`                                     |
| Rate-limit     | pagination only; **no backoff/retry**                                                                     | `github_connector.py`                                      |
| kg_writer.py   | **absent**                                                                                                | —                                                          |
| run() output   | OCSF **2003**; `repo_inventory.json` + `findings.json` + `summary.md` + (conditional) `code_secrets.json` | `agent.py`                                                 |

**Net-new:** B-2 SAST language/ruleset expansion · B-3 multi-tenant scale + perf · B-4 rate-limit/retry hardening · SCM repo inventory discovery + `kg_writer.py`.

## 2. Goal + scope boundary

- **Goal:** AppSec breadth (more languages, scale, resilience) + write the code-side inventory (repos/commits/builds/IaC) to the SemanticStore.
- **Covers:** Semgrep ruleset/language expansion; multi-tenant scale + perf; rate-limit/retry; SCM repo inventory nodes + the **code-to-cloud `BUILT_FROM`/`DEPLOYED_VIA` edge bridge** (catalogue D.9); kg_writer.
- **Does NOT cover:** the deployed cloud resources (D.3/D.5 own; D.9 writes `BUILT_FROM`/`DEPLOYED_VIA` onto them); the per-tenant credential store (SAFETY-CRITICAL substrate — operator-gated, see §7); runtime behavior (D.3 Runtime).

## 3. Approach — per component (options + rec)

- **3a B-2 SAST language/ruleset expansion.** Expand Semgrep config beyond the default community pack (more languages: Go/Ruby/PHP/Java/C# etc.). #23 license: OSS rulesets only, license-vetted, never Pro. Self-merge.
- **3b B-3 multi-tenant scale + perf.** Concurrency + per-repo timeouts + scale tests. **⚠️ the per-tenant credential store is SAFETY-CRITICAL substrate debt** (`credentials.py` raises today) — true multi-tenant SCM auth needs it. **Surface:** is the cred store in v0.4 scope (substrate, operator-gated) or do we scale within the env-var Pattern-A model only?
- **3c B-4 rate-limit/retry.** Backoff + retry on SCM API rate-limit (bounded retry invariant; mirror fleet `assert_bounded_retry`).
- **3d SCM repo inventory + kg_writer.** New `kg_writer.py` (copy-pattern) writing the catalogue's D.9 nodes (Repository/Commit/Branch/PR/Pipeline/Build/IaC/Developer) + `BUILT_FROM`/`COMMITTED_BY`/`DEPLOYED_VIA`/`DEFINED_IN` edges (the **code-to-cloud bridge** — highest-value AppSec graph contribution).

## 4. Sub-PR breakdown (per-PR review — D.14 discipline)

1. PR1 (B-2) Semgrep language/ruleset expansion.
2. PR2 `kg_writer.py` + repo-inventory node schema + `BUILT_FROM`/`DEPLOYED_VIA` edges.
3. PR3 (B-3) concurrency + perf + scale tests (within Pattern-A unless cred store gated in).
4. PR4 (B-4) rate-limit backoff + bounded retry.
5. PR5 cycle verification + coverage doc.

## 5. Substrate, invariants, gates

- Seal EMPTY for the scanner/inventory/kg_writer work (per-agent). **⚠️ per-tenant cred store = SAFETY-CRITICAL substrate** — if pulled into scope it touches the credential boundary (Layer 24); operator-gated, separate handling. Bounded-retry invariant. #23 license discipline. **Per-PR review** (continues D.14). Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. More languages + the code-to-cloud bridge (enables A.4 code-to-cloud attack paths). **Honest:** true multi-tenant SCM auth is bounded by the un-built per-tenant cred store (SAFETY-CRITICAL, may stay deferred); no Semgrep Pro (#23); realized SCM-inventory lift on operator-run of live connectors.

## 7. Open decisions (operator)

1. **Per-tenant credential store** — in v0.4 scope (SAFETY-CRITICAL substrate, operator-gated) or scale within env-var Pattern-A only (rec: defer the cred store unless operator directs)?
2. SAST language priority order (which languages first).
3. Confirm D.9↔D.14 reconciliation (R-2) in catalogue v1.1.

## 8. Template note

Same shape as #712. HOLD: no execution PRs until approved.

## 9. Calendar estimate

~3-4 weeks (per-PR review pace; 5 sub-PRs across 3 work-streams + inventory). Largest Stage 1 sub-milestone; parallel-capable.

## 10. Cross-references

- Catalogue (#711): "D.9 AppSec" (status to fix, R-2) — code-side nodes, `BUILT_FROM`/`DEPLOYED_VIA` bridge, L2-L5.
- Directive §3 Stage 1.6 + Option X. B-1 cycle (#690-707), ADR-014 (SBOM boundary), ADR-015 (secrets→DSPM).
- ADRs: per-tenant cred store may need an ADR if pulled into scope (operator). Related ADR-016 (tool-proxy).
