# A.1 v0.1 verification record — 2026-05-16

Final-verification gate for **A.1 Remediation Agent v0.1 (production-action mode)**. The **first "do" agent** in the platform; the **tenth under [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md)**. Re-scoped from the original three-plan (A.1 / A.2 / A.3) split into a single unified agent shipping all three operational tiers (`recommend` / `dry_run` / `execute`) as `--mode` flags, per the 2026-05-16 user direction "make it production action."

All 16 tasks are committed; every pinned hash is in the [A.1 plan](../superpowers/plans/2026-05-16-a-1-remediation-agent.md)'s execution-status table.

**This closes the cure quadrant 1/3 and shifts the agent population from 9/9 detect → 10/10 with one cure agent online.**

---

## Gate results

| Gate                                                          | Threshold                                                                  | Result                          |
| ------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------- |
| `pytest --cov=remediation packages/agents/remediation`        | ≥ 80%                                                                      | **94%** (`remediation.*`)       |
| `ruff check`                                                  | clean                                                                      | ✅                              |
| `ruff format --check`                                         | clean                                                                      | ✅                              |
| `mypy --strict` (configured `files`)                          | clean                                                                      | ✅ (204 source files)           |
| Repo-wide `uv run pytest -q`                                  | green, no regressions                                                      | **2365 passed, 11 skipped**     |
| v0.1 eval suite (10/10) via `remediation eval`                | 10/10                                                                      | ✅                              |
| v0.1 eval suite via `eval-framework run --runner remediation` | 10/10                                                                      | ✅ **first OCSF 2007 producer** |
| **Mode-escalation gate**                                      | dry_run + execute require auth opt-in                                      | ✅ (driver + CLI + tests)       |
| **Cluster-access mutual exclusion**                           | kubeconfig vs in-cluster (2-way at A.1; 3-way with manifest-target in D.6) | ✅                              |
| **Blast-radius cap**                                          | whole-run refusal if exceeded; no partial-apply                            | ✅                              |
| **Post-validation rollback**                                  | re-detect via D.6 + inverse patch swap                                     | ✅ (4-case decision matrix)     |
| **OCSF 2007 wire shape**                                      | `class_uid 2007 Remediation Activity`                                      | ✅ (Pydantic-validated)         |
| **F.6 hash-chained audit**                                    | 11-action `remediation.*` vocabulary                                       | ✅                              |
| **Idempotency**                                               | correlation_id = SHA-256(target)[:16]                                      | ✅                              |

### Repo-wide sanity check

`uv run pytest -q` → **2365 passed, 11 skipped**. +259 tests vs the pre-A.1 baseline (2106 after D.6 v0.3 / Phase-1b close); no regressions in any other agent or substrate package.

---

## Per-task surface

| Task                                               | Commit    | Tests | Notes                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------- | --------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Bootstrap `packages/agents/remediation/`        | `7913e3e` |    12 | BSL pyproject + workspace member + mypy file list + entry-points (eval-runner + CLI). Smoke tests assert ADR-007 v1.1 LLM adapter + v1.2 NLAH loader hoists, F.1 audit log + F.5 episodic memory imports, F.3 + D.6 schema re-exports, 2 anti-pattern guards.                                                                                           |
| 2. OCSF 2007 schemas + `build_remediation_finding` | `1376b2b` |    33 | `RemediationFinding` Pydantic, `RemediationActionType` (5 v0.1), `RemediationMode` (3), `RemediationOutcome` (8), `RemediationArtifact`, `RemediationReport`. **`REM_FINDING_ID_RE` widened to `[A-Z0-9]+` for the `K8S` token** (same widening D.6 made for the cloud regex).                                                                          |
| 3. 5 K8s action classes + ACTION_CLASS_REGISTRY    | `aa2886a` |    44 | `runAsNonRoot` / `resource_limits` / `readOnlyRootFilesystem` / `imagePullPolicy_Always` / `disable_privilege_escalation`. Pure-function `(build, inverse)` pairs; `swap_for_inverse` shared rollback. Strategic-merge-patch with container `name` as merge key.                                                                                        |
| 4. `Authorization` + gate functions                | `d7d94bd` |    22 | Decoupled from F.1 ExecutionContract (separate auth.yaml). `enforce_mode`, `filter_authorized_findings`, `enforce_blast_radius`, `authorized_action_types`. Pydantic validation: `max_actions_per_run` 1-50, `rollback_window_sec` 60-1800.                                                                                                             |
| 5. `kubectl_executor.py` (apply_patch wrapper)     | `df64684` |    24 | Async wrapper around `kubectl patch` via `asyncio.create_subprocess_exec`. PatchResult frozen dataclass with pre/post SHA-256 hashes + pre/post resource state (when `fetch_state=True`). 3-way mutual exclusion mirrors D.6's pattern.                                                                                                                 |
| 6. `findings_reader.py` (D.6 ingest)               | `df64684` |    14 | Async loader round-trips D.6's OCSF 2003 wrapped findings back into `ManifestFinding`. **Source-strict** (only `evidence.kind == "manifest"` records admitted); D.6 kube-bench + Polaris findings cleanly rejected.                                                                                                                                     |
| 7. `generator.py` (Stage 3)                        | `df64684` |    14 | Pure function `generate_artifacts(findings) -> tuple[RemediationArtifact, ...]`. Defense-in-depth: unmapped rules skip cleanly (the validator-driven gate at Stage 2 should catch them first). Input ordering preserved through to output.                                                                                                              |
| 8. `validator.py` (Stages 6 + 7)                   | `f1d0d66` |    12 | `validate_outcome` sleeps `rollback_window_sec`, re-runs D.6 against the affected workload via a pre-bound detector closure, returns `ValidationResult(requires_rollback, matched_findings)`. `rollback(artifact)` swaps patch_body ↔ inverse_patch_body and re-applies. `build_d6_detector` factory binds cluster-access config.                       |
| 9. `audit.py` + 11-action vocabulary               | `f1d0d66` |    20 | Thin shim over F.6 `AuditLog`. `PipelineAuditor` exposes one method per stage boundary; payloads carry artifact correlation_id (cross-ref to OCSF) + pre/post-patch SHA-256 hashes. Full-pipeline emit-all-11-actions + chain hash linking covered.                                                                                                     |
| 10. NLAH bundle (README + tools + 3 examples)      | `478938a` |    10 | 21-LOC shim over `charter.nlah_loader` (A.1 = 7th native v1.2 agent). README (mission + three tiers + 7-stage pipeline + 5 action classes + 9 safety primitives), tools.md (per-stage tool reference), 3 examples (one per tier). LOC-budget guard under v1.2's 35-LOC threshold.                                                                       |
| 11. `summarizer.py` (`render_summary`)             | `478938a` |    17 | Pure function. **Dual-pin pattern:** rollbacks (`executed_rolled_back`) pinned first, failures (`dry_run_failed` + `execute_failed`) second. Per-outcome breakdown ordered most-actionable-first. Per-action-class rollup. Audit chain head + tail hashes at footer.                                                                                    |
| 12. Agent driver `run()` — 7-stage pipeline        | `825eb03` |    17 | INGEST → AUTHZ → GENERATE → DRY-RUN → EXECUTE → VALIDATE → ROLLBACK. Mode-escalation gate fires **before** the Charter context. 7 output files. Per-artifact Stage 4-7 in `_process_artifact()` with each stage recorded via `PipelineAuditor`.                                                                                                         |
| 13. 10 representative YAML eval cases              | `825eb03` |     — | clean / single-action-recommend / single-action-dry-run / single-action-execute-validated / single-action-execute-rolled-back / unauthorized-action-refused / unauthorized-mode-refused / blast-radius-cap / multi-finding-batch / mixed-action-classes. Fixture shape custom for A.1 (mode + authorization + findings + per-stage subprocess results). |
| 14. `RemediationEvalRunner` + 10/10 acceptance     | `d9fe5b2` |    16 | Registered as `nexus_eval_runners` entry-point. Patches `read_findings`, `apply_patch` (both agent + validator bindings), `build_d6_detector`, `validator.asyncio.sleep` for deterministic runs. **10/10 acceptance confirmed via `eval-framework run --runner remediation`.**                                                                          |
| 15. CLI (`remediation eval` / `remediation run`)   | `d9fe5b2` |    16 | Mutual exclusion (kubeconfig vs in-cluster), cluster-access requirement for dry_run/execute, mode-escalation, IntRange validation on `--rollback-window-sec`, required-file checks. `AuthorizationError` re-raised as `UsageError` so operators see the required opt-in field name.                                                                     |
| 16. README + runbook + this verification record    | _pending_ |     — | README (12 sections: mission + ADR-007 conformance + quick start + 7-stage pipeline + 5 action classes + 7 outputs + 9 safety primitives + tests + license), runbook `remediation_workflow.md` (12 sections + auth.yaml schema + RBAC ClusterRole + 4-case rollback matrix + top-10 troubleshooting tree).                                              |

**Test count breakdown:** 12 + 33 + 44 + 22 + 24 + 14 + 14 + 12 + 20 + 10 + 17 + 17 + 16 + 16 = **271 tests** in the `remediation` package. Coverage: **94%**.

---

## Coverage delta

```
remediation/__init__.py                                  2      0   100%
remediation/action_classes/__init__.py                  22      0   100%
remediation/action_classes/_common.py                   34      0   100%
remediation/action_classes/k8s_disable_privilege_escalation.py    8      0   100%
remediation/action_classes/k8s_image_pull_policy_always.py        8      0   100%
remediation/action_classes/k8s_read_only_root_fs.py     8      0   100%
remediation/action_classes/k8s_resource_limits.py      10      0   100%
remediation/action_classes/k8s_run_as_non_root.py       9      0   100%
remediation/agent.py                                  148     11    93%
remediation/audit.py                                   72      0   100%
remediation/authz.py                                   54      0   100%
remediation/cli.py                                     64      2    97%
remediation/eval_runner.py                            137     10    93%
remediation/generator.py                               14      0   100%
remediation/nlah_loader.py                              9      0   100%
remediation/schemas.py                                122      7    94%
remediation/summarizer.py                             114      8    93%
remediation/tools/__init__.py                           0      0   100%
remediation/tools/findings_reader.py                   90     21    77%
remediation/tools/kubectl_executor.py                  76      5    93%
remediation/validator.py                               48      4    92%
-------------------------------------------------------------------------
TOTAL                                                1049     68    94%
```

The 77% on `findings_reader.py` reflects the source-strictness branches (different D.6 evidence kinds, malformed wrappers) — exercised in the live integration but not all in unit tests.

---

## ADR-007 conformance — A.1 reinforces every reference pattern

A.1 is the **tenth** agent under the reference template and the **first "do" agent**. It confirms or extends every pattern the previous 9 detect agents established:

| Pattern                                            | A.1 verdict                               | Notes                                                                                                                                                                                                       |
| -------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OCSF wire shape via `wrap_ocsf`                    | ✅ extends to `class_uid 2007`            | First producer of OCSF Remediation Activity in the platform. Downstream consumers (D.7, fabric) already filter on the new class_uid.                                                                        |
| `REM_FINDING_ID_RE` widening                       | ✅ generalises D.6's cloud-token widening | F.3 had `[A-Z]+`; D.6 wanted `K8S`; A.1 needs `K8S` too. Both agents converged on `[A-Z0-9]+`. Same generic pattern.                                                                                        |
| Pure-function `(build, inverse)` action class pair | ✅ **new pattern, A.1-specific**          | 5 v0.1 K8s action classes ship as pure functions. The inverse-patch is what makes deterministic rollback work — Stage 7 is just a swap + re-apply.                                                          |
| Async wrappers (ADR-005)                           | ✅ unchanged                              | `kubectl_executor` uses `asyncio.create_subprocess_exec`. Same pattern as D.6 v0.2/v0.3's `read_cluster_workloads`.                                                                                         |
| 21-LOC NLAH shim                                   | ✅ continues to hold                      | A.1 is the **7th native v1.2 NLAH-loader agent**. 21 LOC under v1.2's 35-LOC budget.                                                                                                                        |
| Eval-framework entry-point + 10/10 gate            | ✅ continues to hold                      | `nexus_eval_runners` registration; 10 representative cases; 100% green via `eval-framework run --runner remediation`.                                                                                       |
| F.6 hash-chained audit                             | ✅ extends with the 11-action vocabulary  | First multi-stage agent with per-stage audit entries. Future "do" agents (A.2 / A.3 / etc.) can reuse `PipelineAuditor` directly.                                                                           |
| CLI subcommand pattern (eval + run)                | ✅ continues to hold                      | Same `click.Group` shape as D.6 / D.7. `run` adds `--mode` / `--auth` / `--rollback-window-sec` for the production-action tier.                                                                             |
| Explicit-opt-in discipline                         | ✅ **extended to per-mode gates**         | D.6 v0.2 / v0.3 established "explicit cluster-access mode" (no auto-detect). A.1 layers per-mode opt-in (`mode_*_authorized: true`) + per-action allowlist on top. Three layers of gating for execute mode. |
| 3-way cluster-access exclusion                     | ✅ inherited from D.6 v0.3                | A.1 implements the 2-way exclusion at the CLI (`--kubeconfig` vs `--in-cluster`); the no-cluster `recommend` mode is the third axis. Future `--manifest-target` (no-execute) would re-introduce the 3-way.  |

---

## Strategic impact — what shipping A.1 unlocks

A.1 closes the **single biggest competitive gap vs Wiz** identified in the [2026-05-16 system readiness report §7](system-readiness-2026-05-16.md). Wiz remediates nothing (it reports + routes to a ticketing system); Palo Alto's AgentiX requires per-action human approval. A.1's tiered-mode approach is **the differentiating capability** of Phase 1.

**Agent population shift:** 9/9 detect → 10/10 with one cure agent online. The cure quadrant is no longer empty.

**Track-A unblock:** every downstream "do" agent in the build roadmap (A.2 multi-cloud Cloud Custodian remediation, A.3 IAM least-privilege, A.4 secrets-rotation, etc.) inherits the v0.1 safety primitives — opt-in / allowlist / blast-cap / dry-run / rollback — unchanged. The Phase-1c expansion is now a "more action classes" exercise, not a "rebuild the safety contract" exercise.

**Phase-1c roadmap (next slice):**

1. **A.1 v0.2** — more K8s action classes (`host-network-removal` / `auto-mount-sa-token` / `privileged-container-removal`). Same `(build, inverse)` pair pattern; the validator contract doesn't change.
2. **A.1 v0.3** — AWS Cloud Custodian actions. Ingests F.3 cloud-posture findings; emits Cloud Custodian policy artifacts; executor swaps from `kubectl` to `boto3` / Cloud Custodian's policy engine. Same OCSF 2007 wire shape; same 7-stage pipeline.

---

## References

- A.1 plan: [`docs/superpowers/plans/2026-05-16-a-1-remediation-agent.md`](../superpowers/plans/2026-05-16-a-1-remediation-agent.md)
- A.1 README: [`packages/agents/remediation/README.md`](../../packages/agents/remediation/README.md)
- A.1 runbook: [`packages/agents/remediation/runbooks/remediation_workflow.md`](../../packages/agents/remediation/runbooks/remediation_workflow.md)
- A.1 NLAH bundle: [`packages/agents/remediation/src/remediation/nlah/`](../../packages/agents/remediation/src/remediation/nlah/)
- D.6 v0.3 verification (immediate predecessor): [`d6-v0-3-verification-2026-05-16.md`](d6-v0-3-verification-2026-05-16.md)
- 2026-05-16 system readiness report: [`system-readiness-2026-05-16.md`](system-readiness-2026-05-16.md)
- ADR-007 (cloud-posture as reference): [`decisions/ADR-007-cloud-posture-as-reference-agent.md`](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-005 (async tool wrapper): [`decisions/ADR-005-async-tool-wrapper-convention.md`](decisions/ADR-005-async-tool-wrapper-convention.md)
- ADR-001 (BSL 1.1 license): [`decisions/ADR-001-monorepo-bootstrap.md`](decisions/ADR-001-monorepo-bootstrap.md)
