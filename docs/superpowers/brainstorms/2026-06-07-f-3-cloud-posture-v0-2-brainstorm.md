# F.3 Cloud Posture → Level 2 (v0.2) — Brainstorm (2026-06-07)

> **Cycle 1 of the maturity arc** locked at [PR #244 §4](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md). F.3 is the first agent matured Level 1 → Level 2 (offline → live AWS). This is the **investigation + Q-lock surfacing** stage of the v0.2.5 discipline: _investigate → surface → operator decides → implement._

- **Status:** brainstorm — **NO code, NO plan doc, NO PRs yet.** Awaiting operator Q-locks before a plan is written.
- **Branch:** `docs/f-3-cloud-posture-v0-2-brainstorm`
- **Scope:** F.3 Cloud Posture **only.** No D.5/D.6/other-agent work; no Platform v2.0/v3.0.
- **Method:** 1 currency check (run at HEAD) + 4 parallel read-only investigation agents across 10 axes; findings spot-checked against `origin/main` + live code. File:line citations throughout.
- **Sources (grounded):** [F.3 v0.1 verification](../../_meta/f3-verification-2026-05-10.md) · [agent-version-roadmaps §1](../sketches/2026-05-20-agent-version-roadmaps.md) · [F.3 plan](../plans/2026-05-08-f-3-cloud-posture-reference-nlah.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) · [maturity roadmap](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) · [platform readiness PR #241](../../_meta/nexus-platform-readiness-2026-06-07.md) · D.5 plan Q4 · [v0.2.5 verification drift #8](../../_meta/a-4-meta-harness-v0-2-5-verification-2026-06-07.md).

---

## §0. Executive summary — and the one decision that shapes the cycle

F.3 v0.1 is **healthy and current** (87 tests / 91 collected, 11 src, ruff clean, OCSF 2003 intact — §1). The Level-2 goal per the roadmap is **live boto3 + AWS account autodiscovery**, CSPM 84% → ~90%.

**The single load-bearing finding:** the "live-cloud credential/sandbox substrate" the macro plan calls a _universal Level-2 prerequisite_ turns out to be **two separable things**, and conflating them is the main risk to this cycle:

|                                           | What it is                                                                                                                                                | State today                                                                                                                                                                                                                                  | Risk                                                                                                                                                                 | Blocked?                                                                                                                                                                                                |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **(A) Live credential _resolution_ seam** | A documented convention for _how an agent obtains creds for a run_ — boto3 default chain / `AWS_PROFILE` / explicit session, behind a small resolver seam | **Already works.** boto3 honors `AWS_ENDPOINT_URL` + the default chain today; identity agent already does `boto3.Session(profile_name=…)` ([identity/tools/aws_iam.py:102](../../../packages/agents/identity/src/identity/tools/aws_iam.py)) | **LOW**                                                                                                                                                              | No — single-tenant unblocked                                                                                                                                                                            |
| **(B) Per-tenant credential _store_**     | An encrypted, RLS-scoped F.4 control-plane store agents query for a tenant's cloud creds                                                                  | **Greenfield.** No secret/credential storage exists in control-plane ([control-plane has tenants/auth/rbac only](../../../packages/control-plane/))                                                                                          | **SAFETY-CRITICAL** (touches how the agent reaches customer cloud data — [ADR-011:27-38](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)) | **Yes** — depends on the SET LOCAL tenant-RLS bug ([charter/memory/service.py:96](../../../packages/charter/src/charter/memory/service.py), still present) + deferred to Phase 1c per the D.5 precedent |

**Recommendation (→ Q1):** F.3 v0.2 pioneers **(A) only** — the lightweight credential-_resolution_ seam + a live-AWS test lane, **single-tenant**, LOW-RISK. **(B) the per-tenant store stays a separate, later, SAFETY-CRITICAL cycle**, consistent with the D.5 Q4 deferral and gated behind the tenant-RLS fix. This keeps the _reference pattern_ F.3 establishes honest and reusable without dragging a blocked, customer-data-touching substrate into the first maturity cycle. **The macro plan's "pioneers the substrate" is satisfied by (A)** — the seam every later agent reuses — not by building the F.4 store now.

Everything else (autodiscovery scope, region scoping, eval lane, OCSF continuity) is lower-controversy and detailed below with proposed Q-locks in **§11**.

---

## §1. Axis 1 — F.3 v0.1 currency check ✅ (with reconciled drift)

| Check              | v0.1 record (2026-05-10)                            | At HEAD today                                                                                                                                                                                     | Verdict                     |
| ------------------ | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| Tests              | 94 passed / 3 skipped                               | **87 `def test_` / 91 collected** (14 test files)                                                                                                                                                 | ✅ benign drift             |
| Src files          | 13                                                  | **11**                                                                                                                                                                                            | ✅ benign drift (explained) |
| Coverage           | 96.09%                                              | (not re-run; structure intact)                                                                                                                                                                    | ✅                          |
| OCSF 2003 emission | ✅ `OCSF_CLASS_UID = 2003`                          | ✅ [schemas.py:33](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py)                                                                                                           | ✅                          |
| 3 native checks    | MFA / `*:*` admin / S3 enrichment                   | ✅ intact in [tools/aws_iam.py](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py), [aws_s3.py](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py) | ✅                          |
| LocalStack lane    | gated `NEXUS_LIVE_LOCALSTACK=1`, skip path verified | ✅ [tests/integration/conftest.py:30-58](../../../packages/agents/cloud-posture/tests/integration/)                                                                                               | ✅                          |
| KG-loop closure    | —                                                   | ✅ SemanticStore via [kg_writer.py](../../../packages/agents/cloud-posture/src/cloud_posture/tools/kg_writer.py); neo4j_kg.py dormant                                                             | ✅                          |

**Drift is fully explained, not a regression:** the 13→11 src drop is the **ADR-007 v1.1 LLM-adapter hoist** (`llm.py` → `charter.llm_adapter`, commit `1dfeee0`) plus the `_eval_local` fold; the test delta tracks the KG-loop rewire. **PR #241's "11 src / 87 tests" is the correct current number;** the 2026-05-10 record is simply pre-hoist. No pre-existing issues block Level-2 work.

---

## §2. Axis 2 — Live boto3 substrate (the happy surprise: it mostly already works)

- **boto3 clients are already real calls**, never stubbed in production code. The test _harness_ chooses the target: unit tests use `moto @mock_aws`; integration tests hit LocalStack; **live AWS needs no production-code change** because botocore auto-honors `AWS_ENDPOINT_URL` + the default credential chain. ([tools/aws_iam.py:18](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py), [aws_s3.py:18,42](../../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py), [prowler.py:24-46](../../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py))
- **Credential precedent is locked by D.5 Q4:** _"env vars in v0.1 … mirrors F.3's `AWS_PROFILE` precedent … F.4 per-tenant secret-store lands in Phase 1c."_ This is the explicit, in-repo decision F.3 v0.2 should mirror.
- **Region:** IAM/S3 are global (region param redundant for list ops). Real CSPM wants multi-region — either loop `Session().get_available_regions()` (comprehensive, ~3-5× calls) **or** an operator-supplied `regions` list on the contract (lightweight, operator-scoped). → **Q3.**
- **Error handling for live:** throttling/`ClientError`/eventual-consistency/retry-backoff are new concerns live AWS introduces that LocalStack masks. boto3's built-in adaptive retry covers most; F.3 should surface partial-scan degradation rather than fail-closed. → folds into Q2 scope.
- **LocalStack fixtures stay** alongside a new live lane (no conflict; distinct env gates).

**Net:** the "live boto3 substrate" is ~90% a **test-lane + credential-resolution-seam + region-scoping** exercise, not a rewrite of the tool layer.

## §3. Axis 3 — AWS account autodiscovery (scope it tightly)

- **No STS / Organizations / AssumeRole code exists anywhere** in the repo (grep clean across all agents). Autodiscovery is a pure v0.2 addition.
- **Roadmap split is explicit:** Level 2 = "live boto3 + account autodiscovery"; **Level 3 = "cross-account; Organizations/Control Tower."** So v0.2 autodiscovery should mean **current-account identity confirmation (`sts.get_caller_identity()`) + region enumeration**, _not_ cross-account org traversal. Cross-account `AssumeRole` + `organizations.list_accounts()` = **v0.3**. → **Q4.**
- Minimal new surface: one `tools/aws_account_discovery.py` (STS identity + region list), threaded into the existing `agent.run(aws_account_id=…, aws_region=…)` signature (already present — just drop hardcoded defaults).

## §4. Axis 4 — Credential substrate (the §0 decision, detailed)

- **Control-plane (F.4) today** owns tenants ([tenants/models.py](../../../packages/control-plane/src/control_plane/), ULID-keyed, `auth0_org_id`), RBAC (3 roles, hard-coded table — [auth/rbac.py](../../../packages/control-plane/src/control_plane/)), Auth0 client, FastAPI auth routes, and a charter-audit bridge. **It owns no secret/credential storage** — confirmed greenfield.
- **De-facto mechanism today:** env vars + boto3 default chain; `AWS_PROFILE` for scoping. No agent stores or fetches creds from a service.
- **If/when (B) is built**, its home is a new `control_plane/credentials/` subpackage (models + store + endpoint + RBAC gate, same alembic head as the tenant table). Rough effort if folded in: ~7-8 days **and** it pulls in the tenant-RLS dependency. _This is the argument for keeping it OUT of cycle 1._
- **Single-tenant unblock confirmed:** the SET LOCAL bug fires on _any_ `MemoryService.session(tenant_id)` against real Postgres (syntax error on `$1`), so it gates **multi-tenant isolation and the per-tenant store**, not single-tenant dev. F.3 v0.2 single-tenant proceeds; it must **not newly depend on** the broken RLS path (i.e., live KG persistence to real Postgres stays out of scope — workspace-file findings remain primary). → **Q1 + Q6.**

## §5. Axis 5 — OCSF 2003 / KG / audit continuity ✅ (invariance is structural)

- **2003 is shared, not duplicated:** canonical at [cloud_posture/schemas.py:33](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py); **5 consumers import it** (cloud-posture, multi-cloud, k8s-posture, data-security, compliance) — wire-format continuity is _automatic_, enforced by a re-export test in compliance.
- **Live mode changes the data SOURCE, not the finding SHAPE.** Prowler/boto3 output is wrapped into `CloudPostureFinding` _before_ KG/audit/OCSF emission; `kg_writer` and the dormant `neo4j_kg` consume the same `(finding_id, rule_id, severity, affected_arns)` tuple regardless of source. KG-loop-closure plan already certifies "class_uid unchanged — PASS." **→ no schema work, no consumer regression expected from offline→live.**
- **Audit chain invariant:** same `kg_upsert_*` action vocabulary, same `NexusEnvelope`, regardless of source. Live-mode audit validity unchanged.

## §6. Axis 6 — Eval strategy for Level 2

- **Keep the 10 offline YAML cases unchanged** ([eval/cases/001-010](../../../packages/agents/cloud-posture/eval/cases/)); they remain the deterministic regression gate via `CloudPostureEvalRunner` ([eval_runner.py:31-62](../../../packages/agents/cloud-posture/src/cloud_posture/eval_runner.py), entry-point registered).
- **Add a separate gated live lane** — proposed `NEXUS_LIVE_AWS=1` (distinct from `NEXUS_LIVE_LOCALSTACK`), copying the canonical gate pattern verbatim (env check + socket/endpoint reachability + `pytest.skip` with copy-paste setup instructions; [conftest.py:30-58](../../../packages/agents/cloud-posture/tests/integration/)). → **Q5.**
- **Drift #8 (live-test budget cap) does NOT apply:** F.3 has **no LLM in the detection loop** — deterministic Prowler + IAM + deterministic summarizer ([agent.py:20-24](../../../packages/agents/cloud-posture/src/cloud_posture/agent.py); summarizer is a pure renderer). The drift-#8 `max_metric_calls` cap is a GEPA/LLM concern. F.3's only live cost is **read-only AWS API calls** (cheap/free-tier); the existing `cloud_api_calls=500` budget already bounds it. **Live evals are opt-in for cost-hygiene, not runtime-blowup.**

## §7. Axis 7 — Pattern utility for downstream agents (establish shape now, hoist at #3)

F.3 is the ADR-007 reference agent; its discipline is **"amend on the third duplicate"** (v1.2), with proactive hoist allowed when a pattern is _proven and load-bearing_ (v1.4). Applying that:

| F.3 v0.2 pattern                             | Hoist now?       | Disposition                                                                                                                                                      |
| -------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Credential-resolution seam (A)**           | Not yet          | Establish the _shape_ in F.3 (a `CredentialResolver` protocol defaulting to the boto3 chain). Hoist to `charter` at the **3rd consumer** (F.3 + D.5 + D.2 live). |
| **Account/region autodiscovery**             | Not yet          | F.3 proves it; **#3 consumer** (D.5 Azure subscriptions, D.6 clusters) triggers a `charter.cloud_discovery` hoist (ADR-007 v1.x candidate).                      |
| **Live-mode eval gating (`NEXUS_LIVE_AWS`)** | Doc, not charter | Belongs in the F.2 eval-framework / [ADR-010 version-extension](../../_meta/decisions/ADR-010-version-extension-template.md) template, not charter substrate.    |
| **Offline-fixture-first → live-toggle**      | Doc              | Already the house pattern; codify as the canonical v0.x maturity shape in ADR-010.                                                                               |

**Recommendation:** F.3 v0.2 **writes these shapes cleanly and documents them as hoist candidates** in its verification record; it does **not** pre-emptively hoist (avoids speculative charter churn before the 2nd/3rd consumer exists). This _is_ the "pioneering" the macro plan asks for.

## §8. Axis 8 — Substrate prerequisites + blockers

- **F.5 memory / F.6 audit / F.7 fabric** are all ready to accept live-mode emissions; no coupling that offline→live newly stresses (live changes source, not shape — §5).
- **🔴 SET LOCAL tenant-RLS bug — still present** at [charter/memory/service.py:96](../../../packages/charter/src/charter/memory/service.py) (`SET LOCAL app.tenant_id = :tid` → Postgres rejects `$1`; fix is `SELECT set_config('app.tenant_id', :tid, true)`). **Gates multi-tenant + the per-tenant store (B), not single-tenant F.3 v0.2.** Owner remains the future tenant-RLS substrate-fix cycle. **F.3 v0.2 must not attempt this fix (out of scope) and must not newly depend on the RLS path.**
- **KG-loop cross-run AFFECTS-edge dedup** debt is accepted and unaffected by this cycle.

## §9. Axis 9 — Risk profile + verification methodology

- **Most tasks LOW-RISK** per [ADR-011:34](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) ("test additions, eval-case additions, …"): the live-AWS test lane, region scoping, autodiscovery tool, eval gating — none touch charter or customer-data reachability.
- **SAFETY-CRITICAL trip-wire:** the moment a task touches per-tenant credential storage / how the agent reaches customer cloud data, it's SAFETY-CRITICAL ([ADR-011:27-38](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)) → full review + verified-against-HEAD discipline. **Under the §0 recommendation (A only), cycle 1 stays entirely LOW-RISK.** Choosing (B) flips several tasks to SAFETY-CRITICAL.
- **Verification methodology:** per-task PRs (ADR-011 cadence); cross-agent regression sweep over the 5 OCSF-2003 consumers + KG/audit; **operator-run live smoke** against a real AWS dev account (gated, like the v0.1 smoke runbook); verification record at closure. **No LLM cost** (no model in loop).

## §10. Axis 10 — Proposed task sequence (~12-14 tasks, all LOW-RISK under §0 rec)

> Indicative only — finalized in the plan doc after Q-locks. Assumes Q1 = (A)-only.

|   # | Task                                                                                      | Surface           | Risk |
| --: | ----------------------------------------------------------------------------------------- | ----------------- | ---- |
|   1 | Bootstrap v0.2 branch/version + ADR-010 version-extension pin                             | docs/version      | LOW  |
|   2 | `CredentialResolver` seam (defaults to boto3 chain; `AWS_PROFILE`/explicit-session aware) | cloud-posture src | LOW  |
|   3 | `tools/aws_account_discovery.py` — STS identity + region enumeration                      | cloud-posture src | LOW  |
|   4 | Region scoping (per Q3) threaded through Prowler + IAM + S3                               | cloud-posture src | LOW  |
|   5 | Live-AWS error handling (throttle/retry/partial-scan degradation)                         | cloud-posture src | LOW  |
|   6 | `NEXUS_LIVE_AWS=1` gated live-eval lane (offline 10 untouched)                            | tests             | LOW  |
|   7 | Live-AWS integration tests (read-only) + reachability gate                                | tests             | LOW  |
|   8 | LocalStack lane kept green; coexistence verified                                          | tests             | LOW  |
|   9 | Cross-agent 2003-consumer regression sweep (5 consumers + KG/audit)                       | tests             | LOW  |
|  10 | Operator smoke runbook (real AWS dev account) + README v0.2                               | docs              | LOW  |
|  11 | CSPM coverage re-measure (84% → target ~90%) note                                         | docs              | LOW  |
|  12 | Hoist-candidate documentation (Axis 7) for ADR-007/010                                    | docs              | LOW  |
|  13 | Verification record + cycle closure                                                       | docs              | LOW  |

**Effort:** ~3 weeks at sustainable cadence (matches v0.2.5 empirical). If Q1 = (B), add ~7-8 days + SAFETY-CRITICAL review weight + the tenant-RLS dependency.

---

## §11. Proposed Q-locks (operator decides) 🔒

|      # | Question                                   | Options                                                                                                                                        | **Recommendation**                                                                                                                                         |
| -----: | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1** | **Credential substrate scope for cycle 1** | **(A)** resolution seam only, single-tenant, LOW-RISK · **(B)** also build the per-tenant F.4 store now (SAFETY-CRITICAL, pulls in tenant-RLS) | **(A).** Pioneers the reusable seam; defers the blocked, customer-data-touching store to its proper Phase-1c cycle — consistent with the D.5 Q4 precedent. |
| **Q2** | **"Live boto3" depth in v0.2**             | Minimal (drop hardcoded creds/region, real calls + error handling) · Plus operator credential ergonomics (profile/role flags on CLI)           | **Minimal + CLI `--aws-profile` flag.** Real calls already work; add only ergonomics + live error handling.                                                |
| **Q3** | **Region scoping**                         | All-regions auto (comprehensive, more calls) · Operator-supplied `regions` list (lightweight) · Both (list defaults to all)                    | **Both — `regions` list, default = all available.** Operator control with a sane default.                                                                  |
| **Q4** | **Autodiscovery scope**                    | Current-account identity + region enum (v0.2) · Include cross-account AssumeRole/Organizations now                                             | **Current-account only.** Roadmap explicitly puts cross-account/Organizations at **Level 3 / v0.3.**                                                       |
| **Q5** | **Live-eval gate name + shape**            | `NEXUS_LIVE_AWS=1`, separate lane, 10 offline cases untouched · Extend LocalStack gate                                                         | **New `NEXUS_LIVE_AWS=1` lane.** Distinct cost/reachability profile from LocalStack; keeps offline gate deterministic.                                     |
| **Q6** | **Live KG persistence on real Postgres**   | Out of scope (workspace-file findings only; avoid RLS path) · In scope (forces tenant-RLS fix first)                                           | **Out of scope.** Don't couple cycle 1 to the tenant-RLS blocker; KG persistence already proven offline.                                                   |
| **Q7** | **Hoisting**                               | Establish shapes in F.3, document hoist candidates, hoist at 3rd consumer · Hoist to charter now                                               | **Establish + document, hoist later.** Avoids speculative charter churn before D.5/D.2 v0.2 exist (ADR-007 discipline).                                    |

---

## §12. Cross-agent impact assessment

- **Direct consumers of F.3's 2003 schema (5):** cloud-posture, multi-cloud, k8s-posture, data-security, compliance — **no expected impact** (live changes source, not shape; §5). Regression sweep is a guard, not a fix.
- **Downstream maturity cycles (D.5, D.2, D.1):** inherit F.3's credential-resolution seam + autodiscovery + live-eval-gate shapes. The cleaner F.3 makes these, the cheaper their v0.2s — the core argument for F.3-first.
- **No impact** on D.7/D.12/D.13/A.1/A.4/Supervisor.

## §13. Guardrails (restated)

❌ No code · ❌ No plan doc (next step, _after_ Q-locks) · ❌ No PRs against main · ❌ No scope creep into other agents · ❌ No v2.0/v3.0 work · ❌ Do not touch the tenant-RLS bug · ✅ Pure investigation + recommendations · ✅ Substrate-pioneering scope made explicit (A vs B) · ✅ Pattern-utility documented.

---

## §14. Next step

**Operator: lock Q1–Q7 (or amend).** On lock, the next action is a **plan doc** (`docs/superpowers/plans/2026-06-XX-f-3-cloud-posture-v0-2.md`) decomposing §10 into per-task PRs under ADR-011 cadence — **not** implementation. No code is written until the plan is locked.

— drafted 2026-06-07, F.3 Cloud Posture v0.2 brainstorm (cycle 1 of the maturity arc).
