# F.3 — Cloud Posture v0.2 (Level 1 → Level 2: offline → live AWS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement task-by-task. Steps use checkbox (`- [ ]`) syntax. **Pause for operator review after each numbered task** (ADR-011 per-task PR cadence).

**Goal:** Mature the **Cloud Posture Agent** (`packages/agents/cloud-posture/`, the ADR-007 reference agent) from **v0.1 Level 1** (offline / LocalStack) to **v0.2 Level 2** — live AWS boto3 + current-account autodiscovery — **single-tenant**, **AWS-only**, **LOW-RISK**. Cycle 1 of the maturity arc ([PR #244 macro plan §4](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md)).

**Label:** LOW-RISK (this plan doc; no code; substrate seal empty). Every task below is LOW-RISK — the cycle touches **no charter substrate** by construction (Q1 = (A); Q7 = hoist later).

**Target:** CSPM category **84% → ~90%** (macro plan §3). The CSPM family carries the heaviest Wiz weight (**0.35**) and is the largest single Wiz category ([PR #245 benchmark §3](../../_meta/competitive-benchmark-2026-06-08.md)), so a live, demo-credible F.3 is the highest-leverage maturity start.

**Estimated effort:** ~13 tasks, **~3 weeks** at v0.2.5 sustainable cadence.

**Status at drafting (2026-06-07):** Drafted against operator-confirmed Q-locks. **PR #247 is held pending PR #246 (brainstorm) merge** per operator. Note: the strategic anchor [PR #244](../../strategy/nexus-agent-maturity-roadmap-2026-06-07.md) is **OPEN/in-review** at drafting time — the cycle is locked by operator Q-lock, not by #244's merge; framing may refine if #244 changes in review.

**Source brainstorm:** [`2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md`](../brainstorms/2026-06-07-f-3-cloud-posture-v0-2-brainstorm.md) (PR #246). This plan is a pure decomposition of its **§10** under the **§11 Q-locks**.

---

## Operator-confirmed Q-locks (the resolutions that shape this plan)

| #      | Lock                                                               | Plan consequence                                                                                                                                                                                                                      |
| ------ | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1** | **(A) credential-_resolution_ seam only**, single-tenant, LOW-RISK | A `CredentialResolver` seam lives **in the cloud-posture package** (not charter). The per-tenant F.4 credential **store (B)** — SAFETY-CRITICAL, blocked by the SET LOCAL tenant-RLS bug — is **out of scope** (its own later cycle). |
| **Q2** | Minimal live boto3 + CLI `--aws-profile`                           | Production boto3 calls already work live (botocore honors `AWS_ENDPOINT_URL` + default chain); the cycle adds the resolver seam, a `--aws-profile` flag, and live error handling — **not** a tool-layer rewrite.                      |
| **Q3** | `regions` list, default = all available                            | A `--regions` CLI/contract option threads through Prowler + S3; default enumerates `Session().get_available_regions()`.                                                                                                               |
| **Q4** | Current-account autodiscovery only                                 | `sts.get_caller_identity()` + region enumeration. **Cross-account AssumeRole / Organizations = v0.3** — explicitly deferred.                                                                                                          |
| **Q5** | `NEXUS_LIVE_AWS=1` new gated live-eval lane                        | A new env-gated live lane; the **10 offline eval cases stay byte-untouched** as the deterministic regression gate.                                                                                                                    |
| **Q6** | Live KG persist on real Postgres **out of scope**                  | The cycle does **not** newly depend on the broken RLS path; workspace-file findings remain primary. KG persistence stays as proven offline.                                                                                           |
| **Q7** | Establish + document patterns; hoist at ADR-007 third consumer     | F.3 establishes the resolver / autodiscovery / live-eval-gate **shapes** and documents them as hoist candidates; **no charter hoist this cycle** (avoids speculative substrate churn before D.5/D.2 v0.2 exist).                      |

---

## Architecture overview

v0.2 is **the same agent, live data source** — the offline→live transition changes the _source_ of findings, not their _shape_ (brainstorm §5; KG-loop closure already certified `class_uid 2003` invariant). The 7-stage pipeline, OCSF 2003 emission, audit chain, and KG write path are unchanged.

```
ExecutionContract (signed, single-tenant)
        │  + CredentialResolver (Q1-A: boto3 chain / AWS_PROFILE / explicit session)
        │  + region scope (Q3: --regions, default = all available)
        ▼
┌────────────────────────────────────────────────────────────────────┐
│ Cloud Posture Agent driver (UNCHANGED 7-stage pipeline)            │
│  Stage 0: RESOLVE creds (NEW seam) + autodiscover account (NEW)    │
│  Stage 1: SCAN     — Prowler + IAM + S3, now LIVE per region       │
│  Stage 2-7: NORMALIZE → SCORE → SUMMARIZE → HANDOFF (unchanged)    │
└─────────┬──────────────────────────────────────────────────────────┘
          │  data SOURCE changed (live boto3); finding SHAPE unchanged
          ▼
   findings.json (OCSF 2003) · report.md · audit chain  ← all invariant
```

**What changes:** credential resolution seam, current-account autodiscovery, region scoping, live-AWS error handling, a `NEXUS_LIVE_AWS=1` test/eval lane. **What does NOT change:** OCSF 2003 wire shape, the 7-stage driver, `kg_writer`/`neo4j_kg`, audit vocabulary, the 10 offline eval cases, the summarizer (deterministic — no LLM in loop).

---

## How the brainstorm resolutions shape this plan

- **No charter touch → substrate seal empty.** The `CredentialResolver` is an in-package seam (Q1-A, Q7). The WI-1 substrate-seal guard should **not** trip; if it does, that is a scope error to fix, not bypass.
- **AWS-only, single-tenant.** No multi-cloud (that is D.5's arc); no per-tenant store (that is the deferred (B) cycle).
- **Live changes source, not shape** → the cross-agent 2003-consumer regression sweep (Task 9) is a _guard_, not a _fix_.
- **No LLM in loop** → no token cost; drift-#8 budget cap is N/A. Only live-AWS read-API cost applies (cheap/free-tier), bounded by the existing `cloud_api_calls=500` budget.

---

## Depends on (prior PRs / cycles)

- **F.3 v0.1** ([verification](../../_meta/f3-verification-2026-05-10.md)) — the agent being matured; currency confirmed in brainstorm §1 (87 tests / 91 collected, 11 src, OCSF 2003 intact; 13→11 src is the benign ADR-007 v1.1 LLM-adapter hoist).
- **ADR-010** ([version-extension template](../../_meta/decisions/ADR-010-version-extension-template.md)) — the vN→vN+1 within-agent pattern (D.6 established it twice); F.3 v0.2 is the next instance (Task 1 pins it).
- **ADR-007** — reference-agent shape; F.3 v0.2 establishes new Level-2 shapes as hoist candidates (Q7).
- **ADR-011** — per-task PR cadence + risk labels.
- **PR #244** (macro plan §4) + **PR #245** (benchmark — CSPM 0.35) — strategic anchors (#244 in review at drafting).

## Defers (explicitly out of scope — honor the Q-locks)

- **Per-tenant credential store (B)** — F.4 control-plane `credentials/` subpackage; SAFETY-CRITICAL; blocked by the SET LOCAL `$1` tenant-RLS bug ([charter/memory/service.py:96](../../../packages/charter/src/charter/memory/service.py)). Its own later cycle. (Q1)
- **Cross-account scanning** — STS AssumeRole + `organizations.list_accounts()` → **v0.3** (Q4).
- **Multi-cloud (Azure/GCP)** — D.5's arc, not F.3 (F.3 is AWS-only by architecture).
- **Live KG persistence on real Postgres** — out of scope (Q6); do not couple to the tenant-RLS blocker.
- **Charter hoist of the new shapes** — deferred to the 3rd consumer (Q7).
- **Wazuh extraction** — not folded in; unrelated to this cycle.
- **Pattern-library expansion 700→1,200+ / Organizations / Control Tower** — Level 3 / v0.3 (macro plan §3).

---

## Cross-cutting concerns

1. **Substrate seal empty.** No `packages/charter/**` changes. The resolver seam is `cloud_posture`-local.
2. **Single-tenant only.** No `MemoryService.session(tenant_id)` on real Postgres in any new path (Q6).
3. **Offline determinism preserved.** The 10 offline eval cases stay byte-identical; CI never requires live AWS.
4. **Credential hygiene.** The resolver must never log/persist secrets; it returns a `boto3.Session`, not raw keys. Workspace-scoped outputs only.
5. **Honest live-coverage claim.** The CSPM 84%→~90% target is an **[estimate]** until a measured re-score (Task 11); state it as such.

## Risks

1. **Live AWS throttling / eventual consistency** — boto3 adaptive retry covers most; F.3 should surface **partial-scan degradation** rather than fail-closed (Task 5). Mitigation: per-region try/except → `degraded` markers in `report.md`.
2. **`--regions` default-all latency/cost** — all-region enumeration multiplies API calls. Mitigation: default-all is operator-overridable via `--regions`; read-only calls are free-tier-cheap; bounded by `cloud_api_calls=500`.
3. **Credential misconfiguration in live mode** — surfaces as `NoCredentialsError`/`ClientError`. Mitigation: the resolver raises a clean, actionable error (no stack-trace leak); runbook documents setup (Task 10).
4. **Live lane masking offline regressions** — Mitigation: offline 10 cases remain the required CI gate; live lane is opt-in only (Task 6/8).
5. **2003-consumer drift** — low (shape invariant), but swept explicitly (Task 9) across all 5 consumers + KG/audit.

---

## Tasks 1–13

> All LOW-RISK. Each task = one PR, ADR-011 cadence (standard review; CI green on required checks; no auto-merge to main without review). `~N tests` = indicative.

### Milestone 1 — Bootstrap (1 task)

| #    | Risk     | Title                                               | Description                                                                                                                                                                                                                                                                                   |
| ---- | -------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | —        | v0.2 plan doc                                       | This document. Merged as a LOW-RISK doc-only PR (#247), **held pending PR #246 merge**.                                                                                                                                                                                                       |
| 1    | LOW-RISK | Bootstrap v0.2 — version bump + ADR-010 pin + smoke | Bump `pyproject.toml` `0.1.0` → `0.2.0`. Pin F.3 v0.2 as an [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) version-extension instance (docs-only). Smoke tests: v0.2 imports, 10 eval cases still load (no regression), OCSF 2003 constant unchanged. ~8 smoke tests. |

### Milestone 2 — Live AWS core (4 tasks)

| #   | Risk     | Title                                 | Description                                                                                                                                                                                                                                                                                                       |
| --- | -------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2   | LOW-RISK | `CredentialResolver` seam (Q1-A, Q2)  | New in-package seam: resolves a `boto3.Session` from the boto3 default chain, `AWS_PROFILE`, or explicit profile. Add `--aws-profile` to `cli.py`. Defaults preserve current behavior (env/default chain). **In `cloud_posture`, not charter** (Q7). Never logs secrets. ~12 tests (mocked sessions).             |
| 3   | LOW-RISK | `tools/aws_account_discovery.py` (Q4) | New tool: `sts.get_caller_identity()` (current account id) + region enumeration (`Session().get_available_regions("ec2")`). Threads `aws_account_id` into the existing `agent.run(...)` signature (drop hardcoded defaults). **Current-account only** — no AssumeRole/Organizations. ~10 tests (moto/mocked STS). |
| 4   | LOW-RISK | Region scoping (Q3)                   | Add `--regions` CLI + contract option; default = all available. Thread region list through Prowler (`--region` per invocation), S3 describe, IAM (global — call once, not per region). ~10 tests.                                                                                                                 |
| 5   | LOW-RISK | Live-AWS error handling               | Throttle/`ClientError`/eventual-consistency handling + retry-backoff reliance; **partial-scan degradation** (per-region failure → `degraded` marker, not whole-run failure). Clean, secret-free error surfaces. ~10 tests (mocked failures).                                                                      |

### Milestone 3 — Eval + test lanes (3 tasks)

| #   | Risk     | Title                                        | Description                                                                                                                                                                                                                                                                                                                                      |
| --- | -------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 6   | LOW-RISK | `NEXUS_LIVE_AWS=1` gated live-eval lane (Q5) | New env-gated lane (env check + credential/identity reachability + `pytest.skip` with copy-paste setup), mirroring the `NEXUS_LIVE_LOCALSTACK` pattern ([conftest.py:30-58](../../../packages/agents/cloud-posture/tests/integration/)). **10 offline cases untouched** as the deterministic gate. No `max_metric_calls` cap (no LLM). ~6 tests. |
| 7   | LOW-RISK | Live-AWS integration tests (read-only)       | New `tests/integration/test_agent_aws_live.py` gated by `NEXUS_LIVE_AWS=1`: real read-only scan of a dev account, assert OCSF 2003 output shape + audit-chain validity. Operator-run (like the v0.1 smoke). ~6 tests.                                                                                                                            |
| 8   | LOW-RISK | LocalStack lane coexistence                  | Keep the `NEXUS_LIVE_LOCALSTACK` lane green alongside the new `NEXUS_LIVE_AWS` lane (distinct gates, no conflict); verify both fixtures coexist. ~4 tests.                                                                                                                                                                                       |

### Milestone 4 — Validation + closure (5 tasks)

| #   | Risk     | Title                                      | Description                                                                                                                                                                                                                                                            |
| --- | -------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 9   | LOW-RISK | Cross-agent 2003-consumer regression sweep | Run the full suites of the **5 OCSF-2003 consumers** (cloud-posture, multi-cloud-posture, k8s-posture, data-security, compliance) + KG/audit paths; confirm the offline→live change leaves the shared wire shape green. A guard, not a fix. ~sweep (no new prod code). |
| 10  | LOW-RISK | Operator smoke runbook + README v0.2       | Update `runbooks/aws_dev_account_smoke.md` for live v0.2 (creds setup, `--aws-profile`, `--regions`, `NEXUS_LIVE_AWS=1`, degraded-scan reading); rewrite README to v0.2 (Level 2, live AWS, single-tenant, what's deferred to v0.3). Docs-only.                        |
| 11  | LOW-RISK | CSPM coverage re-measure note              | Measure/record CSPM coverage delta (84% → target ~90%); tag the result **[estimate]** unless instrumented. Honest no-delta finding acceptable. Docs-only.                                                                                                              |
| 12  | LOW-RISK | Hoist-candidate documentation (Q7)         | Document the resolver / autodiscovery / live-eval-gate shapes as ADR-007/ADR-010 **hoist candidates** for the 3rd consumer (D.5/D.2 v0.2). No charter change. Docs-only.                                                                                               |
| 13  | LOW-RISK | Verification record + cycle closure        | `docs/_meta/f-3-cloud-posture-v0-2-verification-2026-XX-XX.md` (date at closure): execution table, Q-lock mapping, gates, cross-agent sweep result, coverage note, watch-items, deferred-(B) handoff.                                                                  |

---

## File map (target)

```
packages/agents/cloud-posture/
  pyproject.toml                                  # 0.1.0 → 0.2.0 (Task 1)
  src/cloud_posture/
    credentials.py                  (NEW)         # CredentialResolver seam (Task 2)
    tools/aws_account_discovery.py  (NEW)         # STS identity + region enum (Task 3)
    tools/{aws_iam,aws_s3,prowler}.py             # region threading + resolver use (Task 4-5)
    cli.py                                        # --aws-profile, --regions (Task 2,4)
  tests/integration/
    conftest.py                                   # NEXUS_LIVE_AWS fixture (Task 6)
    test_agent_aws_live.py          (NEW)         # live read-only lane (Task 7)
  runbooks/aws_dev_account_smoke.md               # v0.2 live (Task 10)
  README.md                                       # v0.2 (Task 10)
docs/_meta/decisions/ADR-010-version-extension-template.md   # F.3 v0.2 pin (Task 1,12)
docs/_meta/f-3-cloud-posture-v0-2-verification-2026-XX-XX.md (NEW)   # closure (Task 13)
```

**Not touched:** `packages/charter/**` (substrate seal empty), the 10 `eval/cases/*.yaml` (byte-identical), `schemas.py` OCSF 2003 (invariant), `kg_writer.py`/`neo4j_kg.py` (Q6).

## Watch-items (carry-forward to verification record)

- **WI-1** — substrate seal must stay empty; resolver is `cloud_posture`-local (Q7). If a charter change feels needed, STOP — re-scope.
- **WI-2** — deferred-(B) handoff: record the per-tenant credential-store scope + the tenant-RLS-fix dependency for its future cycle.
- **WI-3** — `--regions` default-all cost/latency observed on the live smoke; note actual region count + runtime.
- **WI-4** — CSPM coverage claim is an [estimate] until measured (Task 11).
- **WI-5** — hoist candidates (Q7) logged for D.5/D.2 v0.2 to inherit.

## Done definition

1. 10 offline eval cases green (byte-identical); ruff + mypy strict clean.
2. `NEXUS_LIVE_AWS=1` live lane green on an operator-run dev account (read-only); LocalStack lane still green.
3. Current-account autodiscovery + `--regions` (default all) + `--aws-profile` working; partial-scan degradation surfaces cleanly.
4. OCSF 2003 wire shape invariant; 5-consumer + KG/audit regression sweep green.
5. Runbook + README at v0.2; CSPM coverage note recorded ([estimate]-tagged).
6. Substrate seal empty; single-tenant; no KG-on-Postgres dependency.
7. Verification record filed; deferred-(B) + v0.3 (cross-account) handoffs recorded.

## ADR-011 cadence (per-task discipline)

- **All tasks LOW-RISK:** standard review; CI green on required checks (`typescript-tests`, `typescript`, `go`, `python-tests`); per-task PR; no auto-merge without review.
- **No SAFETY-CRITICAL tasks this cycle** — by construction (Q1-A keeps the customer-data-reachability surface, the per-tenant store, out of scope). If any task starts to touch charter or per-tenant credential storage, it has left scope → STOP and re-plan.

## Reference template

F.3 v0.1 itself (same agent, live source) + ADR-010 version-extension pattern (D.6 v0.2/v0.3 precedent). F.3 v0.2 is structurally v0.1 with: (a) a credential-resolution seam; (b) current-account autodiscovery; (c) region scoping; (d) a gated live-AWS lane — all against an unchanged OCSF 2003 / 7-stage / audit core.

---

— drafted 2026-06-07 (F.3 Cloud Posture v0.2 plan; cycle 1 of the maturity arc). PR #247 held pending PR #246 merge.
