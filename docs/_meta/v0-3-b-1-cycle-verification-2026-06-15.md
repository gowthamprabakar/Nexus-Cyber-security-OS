# v0.3 / Phase D — B-1 cycle verification record: D.14 AppSec agent (2026-06-15)

> Closes the **B-1 cycle** — the v0.3 pilot of a **net-new agent**, D.14 AppSec
> (build-time IaC + SAST + secrets-in-code over SCM repositories). Records what
> shipped, the cross-agent + OCSF contracts, verification evidence, the substrate
> seal, and the honest deferrals to later B-cycles. Mirrors the A-2 cycle
> verification (#687).

## 1. What shipped (10 PRs, per-PR operator review)

| PR   | B-1  | What                                                                                       |
| ---- | ---- | ------------------------------------------------------------------------------------------ |
| #690 | PR1  | Scaffold D.14 agent + **ADR-014** (SBOM boundary) + repo discovery + ScmCredentialResolver |
| #691 | PR2  | Checkov IaC scanner → **OCSF 2003** (`appsec_iac_misconfiguration`)                        |
| #694 | PR3  | gitleaks secrets-in-code → **redacted** `code_secrets.json` handoff (producer, ADR-015)    |
| #695 | PR4  | DSPM **consumes** code-secrets → OCSF 2003 `SECRET_EXPOSED_IN_CODE` (loop closed)          |
| #697 | PR5  | Live **GitHub** SCM connector (httpx, Pattern-A auth, injectable client)                   |
| #699 | PR6  | Clone discovered repos for scanning (shallow, token hard-redacted)                         |
| #701 | PR7  | **GitLab + Bitbucket** SCM connectors                                                      |
| #702 | PR8  | **Semgrep** OSS SAST scanner → OCSF 2003 (`appsec_sast_finding`)                           |
| #705 | PR9  | Full-pipeline (3 scanners compose) + **multi-tenant** integration tests                    |
| #706 | PR10 | **eval_runner** + 6 golden cases + `nexus_eval_runners` entry-point (fleet eval parity)    |

> **PR-numbering correction (verify-against-main):** the close-stretch directive
> referenced "#692/#693 IaC Checkov" — verified against main, those are **A-4**
> (identity, #692) and **A-3 PR2** (cloud-posture, #693). The B-1 Checkov IaC PR is
> **#691** (a single PR). The table above is the accurate B-1 membership.

## 2. The contracts (the seams)

- **OCSF 2003 unification (operator decision):** all D.14 findings emit OCSF class
  **2003 Compliance Finding**, distinguished by an `AppSecFindingType` discriminator on
  `finding_info.types[0]` + `evidence.source_finding_type` (the posture-fleet pattern).
  The directive's "2002 Application Misconfiguration" was imprecise — 2002 is
  Vulnerability/CVE-shaped + D.1-owned; 2003 matches the posture fleet.
- **Secrets-in-code cross-agent (ADR-015):** D.14 SCANS (gitleaks) and writes a
  **redacted** `code_secrets.json` (same shape as D.1's `runtime_secrets.json` so one
  DSPM ingester consumes both); **DSPM EMITS** OCSF 2003 `SECRET_EXPOSED_IN_CODE`.
  Matched plaintext (gitleaks `Secret`/`Match`) is NEVER read or written.
- **SBOM boundary (ADR-014):** AppSec owns **build-time**, D.1 owns **deploy-time**;
  D.1 unchanged; shared SBOM schema deferred.
- **Credentials (Pattern-A):** `ScmCredentialResolver` resolves `GITHUB/GITLAB/BITBUCKET_TOKEN`
  at call time, never stored; tokens injected only as subprocess args on clone, never
  logged/returned.

## 3. Privacy boundary (hard, verified both ends)

The secrets-in-code path honors the same hard boundary as A-2.4: D.14's
`gitleaks_to_secret_hits` carries only categorical fields (rule_id / file / line); the
plaintext is dropped at the producer. The PR9 full-pipeline integration test asserts the
plaintext (`AKIA…`) is **absent** from `code_secrets.json` end-to-end; DSPM (#695)
consumes categorical metadata only.

## 4. Verification evidence

- **Per-PR:** each B-1 PR went through per-PR operator review; each green on all 5 CI
  checks (`go, python, python-tests, typescript, typescript-tests`) before merge.
- **Full pipeline (#705):** the three scanners compose in a single `run()` →
  `findings.json` carries **both** OCSF 2003 discriminators + `code_secrets.json` carries
  the redacted handoff.
- **Multi-tenant (#705):** two tenants scanned into separate workspaces each tag findings
  with their own `metadata.tenant_uid` (= `customer_id`); no cross-tenant leak.
- **Eval parity (#706):** `AppSecEvalRunner` satisfies the `EvalRunner` Protocol;
  `run_suite` over all 6 golden cases passes with valid audit chains — the D.14
  acceptance gate (same shape as vulnerability / cloud-posture).
- **Final suite:** appsec **67 pass**; ruff + mypy clean.

## 5. Substrate seal — preserved across the full cycle

`packages/shared` + `packages/charter` diff **EMPTY** across all 10 PRs. D.14 is a new
workspace member registered only in the **root** `pyproject.toml` (workspace registration
is not substrate); `schemas.py` of shared/charter never touched. OCSF discriminators are
agent-local `AppSecFindingType` enum members (additive). No charter hoist.

## 6. Coverage (weighted contribution)

See `d-14-appsec-v0-3-coverage-2026-06-15.md`. D.14 is a **net-new agent** (not in the
#647 baseline) → it adds a **new build-time detection surface** (IaC + SAST + secrets),
not a re-rated existing row. All figures `[estimate]`; **live SCM lift is realized when an
operator runs the connectors**, not by the wiring alone (baseline reconciliation #670,
caveat 4). Secrets-in-code attributes to **DSPM** (ADR-015), not double-counted.

## 7. Honest limitations / deferrals (→ B-2/B-3/B-4 / v0.4)

- **Breadth-not-depth:** one OSS engine per family (Checkov / Semgrep / gitleaks), default
  rulesets; no custom-rule authoring, no Semgrep Pro (#23).
- **DAST / runtime app testing:** out of build-time scope.
- **AppSec build-time SBOM emission:** ADR-014 names the boundary; the emission itself is a
  later B-cycle (D.1 deploy-time SBOM unchanged here).
- **License/policy compliance, dependency-graph reachability for app deps:** not built.
- **Live connectors are gated/operator-run:** offline default is deterministic +
  byte-identical; the live-SCM lift is realized on operator run.

## 8. B-1 cycle status — CLOSED

| PR group                                             | Status                |
| ---------------------------------------------------- | --------------------- |
| Substrate + discovery (PR1)                          | ✅ #690               |
| Scanners — IaC / secrets / SAST (PR2/3/8)            | ✅ #691 / #694 / #702 |
| Secrets-in-code consumer (PR4)                       | ✅ #695               |
| Live SCM — GitHub/GitLab/Bitbucket + clone (PR5/6/7) | ✅ #697 / #699 / #701 |
| Integration + multi-tenant (PR9)                     | ✅ #705               |
| Eval parity (PR10)                                   | ✅ #706               |

**B-1 CYCLE → CLOSED.** Track B v0.3 pilot complete — D.14 AppSec is live on main,
fleet-eval-registered, with the secrets-in-code loop closed end-to-end into DSPM.

## 9. References

- ADR-014 — `decisions/ADR-014-sbom-ownership-boundary.md` (build-time vs deploy-time).
- ADR-015 — `decisions/ADR-015-secrets-in-runtime-ownership-boundary.md` (scan/emit split).
- Coverage — `d-14-appsec-v0-3-coverage-2026-06-15.md`.
- A-2 cycle verification precedent — `v0-3-a-2-4-verification-2026-06-15.md` (#687).
- OCSF-class decision — operator AskUserQuestion (2003, not 2002), recorded at PR2 (#691).
