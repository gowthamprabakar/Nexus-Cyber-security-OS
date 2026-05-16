# A.1 — Remediation Agent v0.1 (production-action mode)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Pause for review after each numbered task.

**Goal:** Ship the **Remediation Agent** (`packages/agents/remediation/`) — the **first "do" agent** in the platform. Consumes OCSF findings from any detect agent (initially D.6 Kubernetes Posture, later D.1 / F.3 / D.5) and **generates + optionally executes remediation artifacts** against the live cluster, with safety primitives that make production action safe.

**Scope (re-scoped per user direction).** The original build-roadmap split remediation across three sequential plans (A.1 recommend-only / A.2 approve-and-execute / A.3 autonomous). Per the 2026-05-16 user direction "try to make it production action," this single A.1 plan ships **all three operational tiers as `--mode` flags on one agent**, gated by safety primitives that match each mode's blast radius:

- **`--mode recommend`** (default, lowest blast radius) — generate artifacts only; no execution; equivalent to the original A.1 Tier-3 scope.
- **`--mode dry-run`** — execute against `kubectl --dry-run=server`; reports diff but applies nothing; equivalent to a "preview" Tier-2.
- **`--mode execute`** — apply for real, with mandatory rollback-timer + post-validation; equivalent to original A.3 Tier-1 with narrow action set.

The `execute` mode is **only allowed when explicitly authorised in the `ExecutionContract`** (a new `remediation_authorized_actions` field + `remediation_mode_execute_authorized: bool` gate). Per-run defaults to `recommend`; the operator must opt in to higher tiers.

**Strategic role.** Closes the **single biggest competitive gap vs Wiz** identified in the [2026-05-16 system readiness report §7](../../_meta/system-readiness-2026-05-16.md). Wiz remediates nothing; Palo Alto's AgentiX requires per-action approval. A.1's tiered-mode approach is **the differentiating capability** of Phase 1. First "do" agent unblocks every downstream Track-A roadmap item and shifts the agent population from 9/9 detect → 10/10 with one cure agent online.

---

## Resolved questions

| #   | Question                                                | Resolution                                                                                                                                                                                                                                                                                                                                                                                                       | Task   |
| --- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| Q1  | Standalone agent or sub-component of D.7 Investigation? | **Standalone agent** (`packages/agents/remediation/`, Agent #10 under ADR-007). PRD §1.3 lists it independently. Consumes findings.json artifacts from any detect agent via the sibling-workspace pattern (D.7 already does this).                                                                                                                                                                               | Task 1 |
| Q2  | Mode-gating mechanism (recommend / dry-run / execute)?  | **`--mode` CLI flag + ExecutionContract authorization gates.** Default is `recommend`. `dry-run` requires `remediation_mode_dry_run_authorized: true` in the contract. `execute` requires both `remediation_mode_execute_authorized: true` AND a `remediation_authorized_actions: [...]` allowlist of action-class names. **No action class executes unless explicitly named in the contract.**                  | Task 4 |
| Q3  | v0.1 action class scope?                                | **5 K8s patches** sourced from D.6 finding rule_ids. Smallest blast-radius set: `k8s-patch-runAsNonRoot` / `k8s-patch-resource-limits` / `k8s-patch-readOnlyRootFilesystem` / `k8s-patch-imagePullPolicy-Always` / `k8s-patch-disable-privilege-escalation`. Each is a single `kubectl patch` operation on a single workload. Phase-1c v0.2 expands to broader K8s + AWS Cloud Custodian actions.                | Task 3 |
| Q4  | Rollback mechanism for `execute` mode?                  | **Post-validation re-runs the detector on the affected workload(s).** After applying, wait `rollback_window_sec` (default 300s; configurable in contract; capped at 1800s). Re-run D.6 against the same namespace+workload. If the original finding is still present → revert the patch (apply the inverse `kubectl patch`). If the finding is gone → commit; emit audit-chain success.                          | Task 8 |
| Q5  | How does the agent get cluster access?                  | **Reuse D.6 v0.2/v0.3 patterns.** Three deployment modes via `--manifest-target` (no execute; just artifact generation) / `--kubeconfig` (explicit path) / `--in-cluster` (Pod SA token). Mutual exclusion is 3-way like D.6. RBAC for `execute` mode needs `patch` verb on workload kinds (the runbook documents the ClusterRole).                                                                              | Task 5 |
| Q6  | Where does the agent get the findings from?             | **`--findings PATH` flag** pointing at a `findings.json` produced by a detect agent (D.6 / D.5 / F.3 / D.1). Mirrors D.7's `--sibling-workspace` consumption pattern. The agent reads the JSON, filters to findings whose rule_id maps to a known action class, builds artifacts, and (if mode permits) executes.                                                                                                | Task 6 |
| Q7  | What about audit + tenant isolation?                    | **Reuse F.6 hash-chained AuditLog + F.4 tenant-RLS.** Every action enumeration → audit. Every artifact generation → audit. Every dry-run → audit. Every execute → audit (with `pre-patch` hash + `post-patch` hash for tamper-evident chain). Every rollback → audit. The audit chain is the single source of truth for "what did the agent do, when, with what authorization."                                  | Task 9 |
| Q8  | Schema for the agent's output?                          | **New `RemediationFinding` schema** that wraps an OCSF `class_uid 2007 Remediation Activity` (per OCSF v1.3 spec). Discriminator = action_class (e.g. `remediation_k8s_patch_runAsNonRoot`). Downstream consumers (D.7 / fabric) can subscribe to `class_uid 2007` events. **Wire shape independent of input finding shape** — A.1 emits its own OCSF class regardless of which detect agent produced the input. | Task 2 |

---

## Architecture — 7-stage pipeline

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Remediation Agent driver                                          │
│                                                                  │
│  Stage 1: INGEST       — read findings.json from --findings path  │
│  Stage 2: AUTHZ        — filter to authorized action classes;     │
│                          enforce blast-radius cap (max_actions)   │
│  Stage 3: GENERATE     — per finding → RemediationArtifact        │
│                          (kubectl patch JSON / Cloud Custodian)   │
│  Stage 4: DRY-RUN      — kubectl --dry-run=server apply (always   │
│                          runs in dry-run + execute modes)         │
│  Stage 5: EXECUTE      — kubectl apply (execute mode only)        │
│  Stage 6: VALIDATE     — wait rollback_window_sec; re-run D.6 on  │
│                          affected workloads; check finding gone   │
│  Stage 7: ROLLBACK     — if VALIDATE fails → apply inverse patch  │
│                          + audit; if pass → audit success         │
└────────────────┬─────────────────────────────────────────────────┘
                 │
                 ▼
   workspace/
     artifacts/                  ← all modes: per-action kubectl-patch JSON
     remediation_log.json        ← all modes: OCSF 2007 array of attempted actions
     dry_run_diffs.json          ← dry-run + execute modes: server-side diff
     execution_results.json      ← execute mode: pre/post-patch state + outcome
     rollback_decisions.json     ← execute mode: validate-pass/fail per action
     audit.jsonl                 ← F.6 hash-chained chain (every stage emits)
```

**Modes vs stages:**

| Mode      | INGEST | AUTHZ | GENERATE | DRY-RUN | EXECUTE | VALIDATE | ROLLBACK |
| --------- | :----: | :---: | :------: | :-----: | :-----: | :------: | :------: |
| recommend |   ✅   |  ✅   |    ✅    |   ❌    |   ❌    |    ❌    |    ❌    |
| dry-run   |   ✅   |  ✅   |    ✅    |   ✅    |   ❌    |    ❌    |    ❌    |
| execute   |   ✅   |  ✅   |    ✅    |   ✅    |   ✅    |    ✅    |   ✅†    |

† ROLLBACK runs only if VALIDATE fails.

---

## Execution status

| Task | Status  | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---- | ------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done | `7913e3e` | Bootstrap — `packages/agents/remediation/` pyproject (BSL 1.1; deps on charter / shared / eval-framework / nexus-cloud-posture / nexus-k8s-posture-agent / kubernetes). 12 smoke tests: package imports, ADR-007 v1.1 LLM adapter + v1.2 NLAH loader hoists, F.1 audit log + F.5 episodic memory imports, F.3 cloud_posture schema re-export + D.6 ManifestFinding import (the input shapes A.1 consumes), kubernetes SDK ≥31.0.0, 2 anti-pattern guards (no remediation.llm / audit_log / findings_schema), 2 entry-points (eval-runner + console script). Workspace member + mypy file list added. 2106 passed / 11 skipped repo-wide; 185 mypy strict files.                                                                                                                                                                           |
| 2    | ✅ done | `36c0620` | `schemas.py` — first OCSF v1.3 `class_uid 2007 Remediation Activity` producer. Re-exports F.3's substrate (Severity / AffectedResource / NexusEnvelope / wrap*ocsf) + adds REM_FINDING_ID_RE (`^REM-[A-Z0-9]+-\d{3}-[a-z0-9*-]+$`; target widened from F.3's `[A-Z]+`to accept`K8S`), RemediationActionType (5 values), RemediationMode (3), RemediationOutcome (8 + severity map), RemediationArtifact (patch + inverse + lineage), RemediationFinding typed wrapper, build_remediation_finding constructor, RemediationReport aggregate. 33 tests.                                                                                                                                                                                                                                                                                      |
| 3    | ✅ done | `36c0620` | `action_classes/` — 5 v0.1 K8s patch classes (run-as-non-root / resource-limits / read-only-root-fs / image-pull-policy-Always / disable-privilege-escalation). Each is a pure-function builder; all 5 share the `swap_for_inverse` rollback helper. `_common.py` provides api-version-per-kind / correlation_id_for / pod_spec_path_components / wrap_pod_spec_patch / wrap_container_patch / swap_for_inverse. Registry keyed on D.6 ManifestFinding.rule_id; lookup_action_class returns None for unmapped rule_ids (privileged-container / host-\* etc. deliberately deferred). 44 tests. 2183 passed / 11 skipped repo-wide; 193 mypy strict files.                                                                                                                                                                                  |
| 4    | ✅ done | `1aa60c0` | `authz.py` — `Authorization` Pydantic model loaded from a separate `auth.yaml` (decoupled from F.1 ExecutionContract). Four gates: `enforce_mode` / `filter_authorized_findings` / `enforce_blast_radius` / `authorized_action_types`. Defaults to recommend-only; `dry_run` + `execute` must opt in. Error messages name the exact flag to flip. 22 tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 5    | ✅ done | `1aa60c0` | `tools/kubectl_executor.py` — async wrapper around `kubectl patch` via `asyncio.create_subprocess_exec`. Mirrors D.6 v0.2/v0.3 cluster access (explicit `kubeconfig` OR default discovery in-cluster). `--dry-run=server` flag honoured. Returns `PatchResult` (frozen dataclass) with exit_code / stdout / stderr / dry_run / pre+post-patch SHA-256 hashes / parsed pre+post-patch resources. State capture via `kubectl get -o json` before + after the patch. `KubectlExecutorError` raised when kubectl missing. 24 tests with mocked `_run`.                                                                                                                                                                                                                                                                                        |
| 6    | ✅ done | `faaa8f3` | `tools/findings_reader.py` — async loader. Round-trips D.6's `cloud_posture.FindingsReport` JSON back into `k8s_posture.ManifestFinding` records. Source-strict (only `evidence.kind == "manifest"` surfaces; kube-bench / Polaris dropped silently). File-level errors → `FindingsReaderError`; per-finding malformations → silent drop. 14 tests using D.6's real `normalize_manifest` for round-trip realism.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 7    | ✅ done | `faaa8f3` | `generator.py` — Stage 3 pure function `generate_artifacts(findings) -> tuple[RemediationArtifact, ...]`. Per finding, looks up the action class via `lookup_action_class` and calls its `build()`. Defense-in-depth skip for unmapped rules. Determinism guarantee — same input → same output in same order → idempotent correlation_ids. 14 tests including parametrize over all 5 v0.1 rule_ids.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 8    | ✅ done | `f1d0d66` | `validator.py` — Stages 6 + 7. `validate_outcome` sleeps `rollback_window_sec`, re-runs D.6 against the affected workload via a pre-bound detector closure, returns `ValidationResult(requires_rollback, matched_findings)`. Scoped by (namespace, kind, workload_name, container_name). `rollback(artifact)` swaps patch_body ↔ inverse_patch_body and re-applies in execute mode. `build_d6_detector` factory binds cluster-access config. 12 tests covering all four "did the patch fix it?" cases plus rollback shape + window enforcement.                                                                                                                                                                                                                                                                                           |
| 9    | ✅ done | `f1d0d66` | `audit.py` — thin shim over F.6 `AuditLog`. Centralised 11-action vocabulary (`remediation.*`). `PipelineAuditor` exposes one method per stage boundary; payloads carry artifact correlation_id (cross-ref to OCSF finding) + pre/post-patch SHA-256 hashes (tamper-evident chain). Outcome semantics: dry-run-only/failed, execute pending-validation, execute-failed, executed-validated/rolled-back, refused-unauthorized, refused-blast-radius. 20 tests including full-pipeline emits-all-11-actions + chain hash linking.                                                                                                                                                                                                                                                                                                           |
| 10   | ✅ done | `478938a` | NLAH bundle — 21-LOC shim over `charter.nlah_loader` (A.1 = 7th native v1.2 agent). `README.md` (mission + three tiers + 7-stage pipeline + 5 action classes + 9 safety primitives + when-to-use-which-mode), `tools.md` (per-stage tool reference + 11-action audit vocabulary), and 3 examples (one per tier: `01-recommend.md` / `02-dry-run.md` / `03-execute-validated.md`). 10 tests including LOC-budget guard under v1.2's 35-LOC threshold.                                                                                                                                                                                                                                                                                                                                                                                      |
| 11   | ✅ done | `478938a` | `summarizer.py` — pure function `render_summary(report)` → markdown with dual-pin pattern. Pin 1: rollbacks (`executed_rolled_back`). Pin 2: failures (`dry_run_failed` + `execute_failed`). Per-outcome breakdown ordered most-actionable-first. Per-action-class rollup. All-actions section grouped by outcome. Audit chain head+tail hashes pinned at footer with F.6 query hint. 17 tests including deterministic-output + single-trailing-newline.                                                                                                                                                                                                                                                                                                                                                                                  |
| 12   | ✅ done | `825eb03` | Agent driver `run()` — 7-stage pipeline (ingest → authz → generate → dry-run → execute → validate → rollback). `--mode` flag wiring. Mode-escalation gate via `enforce_mode(auth, mode)` fires **before** the Charter context so `AuthorizationError` surfaces to the caller (not buried in workspace cleanup). 7 output files emitted: `findings.json` (OCSF 2007 wrapped), `report.md` (summarizer), `dry_run_diffs.json`, `execution_results.json`, `rollback_decisions.json`, `audit.jsonl`, `artifacts/<correlation_id>.json`. Per-artifact Stage 4-7 in `_process_artifact()` with each stage recorded via `PipelineAuditor`. 17 driver tests covering registry, mode gates, all 8 outcomes, multi-finding ordering, idempotency.                                                                                                   |
| 13   | ✅ done | `825eb03` | 10 representative YAML eval cases — clean / single-action-recommend / single-action-dry-run / single-action-execute-validated / single-action-execute-rolled-back / unauthorized-action-refused / unauthorized-mode-refused / blast-radius-cap / multi-finding-batch / mixed-action-classes. Fixture shape custom for A.1: `mode` + `authorization` (per-mode auth flags, authorized_actions, max_actions_per_run, rollback_window_sec) + `findings` (D.6 ManifestFinding) + per-stage subprocess results (`dry_run_result` / `execute_result` / `rollback_result`) + `post_validate_findings`. Encodes the v0.1 acceptance surface end-to-end.                                                                                                                                                                                           |
| 14   | ✅ done | `d9fe5b2` | `RemediationEvalRunner` registered as the `nexus_eval_runners` entry-point (bootstrapped in Task 1). Fixture parser handles A.1's custom shape (mode + authorization + findings + per-stage subprocess results + post_validate_findings) and patches `read_findings`, `apply_patch` (both agent + validator bindings), `build_d6_detector`, and the validator's `asyncio.sleep` for deterministic eval-time runs. Evaluation compares finding_count / by_outcome / action_types_distinct against `case.expected`; `raises: AuthorizationError` inverts the success check. **10/10 acceptance confirmed via `eval-framework run --runner remediation`** end-to-end. 16 tests.                                                                                                                                                              |
| 15   | ✅ done | `d9fe5b2` | CLI (`remediation eval CASES_DIR` / `remediation run`) with `--contract`, `--findings`, `--auth`, `--mode {recommend,dry_run,execute}`, `--kubeconfig` / `--in-cluster` / `--cluster-namespace`, `--rollback-window-sec` (IntRange 60-1800). Mutual exclusion (kubeconfig vs in-cluster) + cluster-access requirement for non-recommend modes surface as `click.UsageError`. `AuthorizationError` from the agent driver re-raised as `UsageError` so operators see the required opt-in field name in the message. 16 tests including --help/--version, the 10/10 eval gate via CLI, all four gate paths, IntRange validation, and required-file checks.                                                                                                                                                                                   |
| 16   | ✅ done | `72f2d03` | README (12 sections: mission + ADR-007 conformance + quick start with 4 modes + 7-stage pipeline diagram + 5 v0.1 action classes table + 7-output contract + 9 safety primitives + tests + license). Runbook [`runbooks/remediation_workflow.md`](../../../packages/agents/remediation/runbooks/remediation_workflow.md) (12 sections: pre-flight + per-mode operator walkthroughs + auth.yaml schema + RBAC ClusterRole + 4-case rollback decision matrix + 7-output triage + F.6 11-action audit vocabulary + D.7 routing + top-10 troubleshooting + Phase-1c roadmap). Verification record [`docs/_meta/a1-verification-2026-05-16.md`](../../_meta/a1-verification-2026-05-16.md) (94% pkg coverage, 271 tests, 2365 repo-wide passed, 10/10 eval gate, ADR-007 conformance matrix). **First "do" agent shipped; cure quadrant 1/3.** |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [F.6 audit](../../_meta/decisions/ADR-009-memory-architecture.md).

---

## v0.1 action class catalogue

The 5 K8s patch classes shipped in v0.1, sourced from D.6 rule_ids:

| D.6 rule_id                    | Action class                             | What it patches                                                                   | Inverse                                |
| ------------------------------ | ---------------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------- |
| `run-as-root`                  | `k8s-patch-runAsNonRoot`                 | Set `spec.template.spec.securityContext.runAsNonRoot: true` + `runAsUser: 65532`  | Remove the security-context field      |
| `missing-resource-limits`      | `k8s-patch-resource-limits`              | Add `resources.limits.cpu: 500m` + `resources.limits.memory: 256Mi` per container | Remove the resources.limits block      |
| `read-only-root-fs-missing`    | `k8s-patch-readOnlyRootFilesystem`       | Set per-container `securityContext.readOnlyRootFilesystem: true`                  | Set back to false / remove field       |
| `image-pull-policy-not-always` | `k8s-patch-imagePullPolicy-Always`       | Set per-container `imagePullPolicy: Always`                                       | Restore previous imagePullPolicy value |
| `allow-privilege-escalation`   | `k8s-patch-disable-privilege-escalation` | Set per-container `securityContext.allowPrivilegeEscalation: false`               | Set back to true / remove field        |

Each class is a **pure-function pair** (`build` + `inverse`). The kubectl patch payload is JSON-merge-patch (RFC 7396) by default; strategic-merge for paths the K8s API requires it (e.g. `containers` list).

**Deferred to v0.2+:**

- `privileged-container` patch — too high blast-radius for v0.1 (removing privileged may break the workload entirely; better to recommend rather than execute).
- `host-network` / `host-pid` / `host-ipc` patches — same reasoning.
- `auto-mount-sa-token` patch — touches a security-sensitive surface; defer.
- AWS Cloud Custodian-generated remediations from F.3 + D.5 findings — phase-1c v0.2.

---

## Compatibility contract

- **First `class_uid 2007` (Remediation Activity)** producer in the platform. Downstream consumers (D.7 / fabric / Meta-Harness / S.1 console when shipped) will start subscribing to this class.
- **No changes to existing detect agents.** A.1 reads their findings.json files; the detect-side contract is unchanged.
- **ExecutionContract gains 4 new optional fields** under `unmapped`:
  - `remediation_authorized_actions: list[str]` — allowlist of action-class names
  - `remediation_mode_dry_run_authorized: bool` — default false
  - `remediation_mode_execute_authorized: bool` — default false
  - `remediation_rollback_window_sec: int` — default 300; capped 1800
  - `remediation_max_actions_per_run: int` — default 5; capped 50
- **F.6 Audit chain** gets a new entry type: `remediation.{action_attempt,artifact_generated,dry_run,executed,validated,rolled_back}`. F.6 query API surfaces these via the existing 5-axis filter.
- **F.4 tenant RLS** scope unchanged — A.1 reads/writes within the contract's `customer_id` scope only.

---

## Safety primitives (Tier-1 essentials, applied across all modes)

1. **Pre-authorized action allowlist** — only action classes named in `remediation_authorized_actions` can run; un-allowlisted findings are dropped at Stage 2 (AUTHZ) with an audit entry.
2. **Mode-escalation gate** — `dry-run` and `execute` modes require explicit contract authorization. The CLI flag alone is insufficient.
3. **Blast-radius cap** — `remediation_max_actions_per_run` defaults to 5; refusing-with-audit if would exceed.
4. **Mandatory dry-run before execute** — `execute` mode always runs Stage 4 (DRY-RUN) first; a non-zero dry-run exit aborts before Stage 5.
5. **Rollback timer + post-validation** — `execute` mode waits `rollback_window_sec`, re-runs D.6, and auto-reverts on validation failure.
6. **Hash-chained audit per stage** — every action has pre-patch hash + post-patch hash; tamper-evident chain across the full run.
7. **Idempotency** — every artifact has a `correlation_id` derived from the source finding ID; re-running with the same input produces the same artifact (no double-apply).
8. **Workspace-scoped state** — all 6 output artifact files live inside the contract's workspace; nothing outside the workspace gets written.
9. **3-way cluster-access exclusion** — mirrors D.6 v0.3's `--manifest-target` / `--kubeconfig` / `--in-cluster` pattern. `--manifest-target` is a 4th mode that disables Stages 4-7 entirely (artifact-only, even when --mode=execute is set, because no cluster connection exists).

---

## Defers (Phase 1c+ — separate plans)

- **A.1 v0.2 — broader K8s action set** (privileged / host-namespaces / SA-token-mount remediations once the v0.1 safety record is established).
- **A.1 v0.3 — AWS Cloud Custodian actions** (consume F.3 findings; generate Cloud Custodian policies; execute via boto3 with the same safety primitives).
- **A.1 v0.4 — Terraform-emit mode** (alternative to direct kubectl/cloud-custodian execute: generate Terraform plan; operator applies via their own CI).
- **A.2 — ChatOps approval gating** (the original Tier-2 — adds a Slack/Teams approval gate between Stages 4 and 5; depends on S.3 ChatOps).
- **A.4 — Meta-Harness** (reads A.1's audit trail + outcome distribution; proposes adjustments to action-class allowlists, rollback windows, blast-radius caps).

---

## Reference template

**D.6 v0.1 → v0.2 → v0.3** (`2026-05-13-d-6-kubernetes-posture.md` + v0.2 + v0.3 plans) — same ADR-007 reference shape, same 21-LOC NLAH shim pattern, same 3-way cluster-access exclusion (here: artifact-target / kubeconfig / in-cluster), same eval-runner discipline, same v0.1-then-extend version-extension pattern A.1 will follow for v0.2+.

— recorded 2026-05-16
