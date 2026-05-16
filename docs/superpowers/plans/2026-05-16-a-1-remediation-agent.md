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

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---- | ---------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `7913e3e` | Bootstrap — `packages/agents/remediation/` pyproject (BSL 1.1; deps on charter / shared / eval-framework / nexus-cloud-posture / nexus-k8s-posture-agent / kubernetes). 12 smoke tests: package imports, ADR-007 v1.1 LLM adapter + v1.2 NLAH loader hoists, F.1 audit log + F.5 episodic memory imports, F.3 cloud_posture schema re-export + D.6 ManifestFinding import (the input shapes A.1 consumes), kubernetes SDK ≥31.0.0, 2 anti-pattern guards (no remediation.llm / audit_log / findings_schema), 2 entry-points (eval-runner + console script). Workspace member + mypy file list added. 2106 passed / 11 skipped repo-wide; 185 mypy strict files. |
| 2    | ⬜ pending | —         | `schemas.py` — `RemediationFinding` OCSF v1.3 `class_uid 2007 Remediation Activity` wrapper; `RemediationActionType` enum (the 5 v0.1 action classes); `RemediationArtifact` (kubectl-patch payload); `RemediationOutcome` (success / dry-run-only / executed-validated / executed-rolledback); `FINDING_ID_RE` for `REM-K8S-<NNN>-<context>`; `build_remediation_finding` constructor.                                                                                                                                                                                                                                                                         |
| 3    | ⬜ pending | —         | `action_classes/` — 5 v0.1 action classes. Each class is a pure function: `def build(finding: ManifestFinding) -> RemediationArtifact`. Generates the kubectl-patch payload for that rule. Each class also defines `inverse(artifact) -> RemediationArtifact` for rollback. Registered in an `ACTION_CLASS_REGISTRY` keyed by D.6 rule_id (e.g. `run-as-root` → `k8s-patch-runAsNonRoot`).                                                                                                                                                                                                                                                                      |
| 4    | ⬜ pending | —         | `authz.py` — `Authorization` model: reads `remediation_authorized_actions` + `remediation_mode_*_authorized` from `ExecutionContract.unmapped`. `enforce(mode, requested_actions)` raises `AuthorizationError` when the contract doesn't permit the mode/action; `filter_authorized(findings)` drops findings whose action class isn't allowlisted. Blast-radius cap (`max_actions_per_run` from contract).                                                                                                                                                                                                                                                     |
| 5    | ⬜ pending | —         | `tools/kubectl_executor.py` — async wrapper around `kubectl patch` (sync subprocess via `asyncio.to_thread`). Supports the same 3 cluster-access modes as D.6 (`--kubeconfig` / `--in-cluster` / artifact-only). `--dry-run=server` flag honoured. Returns structured result with stdout/stderr/exit-code/pre-patch-hash/post-patch-hash.                                                                                                                                                                                                                                                                                                                       |
| 6    | ⬜ pending | —         | `tools/findings_reader.py` — async loader for `findings.json` produced by detect agents. Validates OCSF shape; filters to findings whose rule_id maps to an action class in the registry (Q3). Returns `tuple[ManifestFinding, ...]` (D.6's shape) for the v0.1 K8s-only scope.                                                                                                                                                                                                                                                                                                                                                                                 |
| 7    | ⬜ pending | —         | `generator.py` — Stage 3 pure function: `generate_artifacts(findings, authz) -> tuple[RemediationArtifact, ...]`. Per finding, looks up the action class in the registry, calls `build()`, attaches finding lineage (links artifact back to source finding ID). Emits one artifact per finding.                                                                                                                                                                                                                                                                                                                                                                 |
| 8    | ⬜ pending | —         | `validator.py` — Stage 6 + 7. `validate_outcome` re-runs D.6 against the affected (namespace, workload) tuples after `rollback_window_sec`. Compares "is the original finding still present?". `rollback` applies the action class's `inverse()` artifact. **Critical safety code; mocked-detector tests + integration-style end-to-end tests both required.**                                                                                                                                                                                                                                                                                                  |
| 9    | ⬜ pending | —         | `audit.py` — wires F.6 `AuditLog` for the 7-stage pipeline. Every stage entry/exit emits an audit entry; every artifact has pre/post-patch SHA-256 hashes; every rollback has its own chain link. Tamper-evident across the full run.                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 10   | ⬜ pending | —         | NLAH bundle + 21-LOC shim (7th native v1.2 agent). README + tools.md + 3 examples (recommend / dry-run / execute). LOC-budget guard test.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 11   | ⬜ pending | —         | `summarizer.py` — render markdown report. Per-action-class breakdown · CRITICAL / HIGH actions pinned · per-outcome summary (validated / rolled-back / dry-run-only) · audit chain head + tail hashes. Mirrors the D.6 dual-pin pattern.                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 12   | ⬜ pending | —         | Agent driver `run()` — 7-stage pipeline. `--mode` flag wiring. Mode-escalation gate (raises if contract doesn't authorize requested mode). Charter ctx emits all 6 artifact files + audit.jsonl.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 13   | ⬜ pending | —         | 10 representative YAML eval cases — clean / single-action-recommend / single-action-dry-run / single-action-execute-validated / single-action-execute-rolled-back / unauthorized-action-refused / unauthorized-mode-refused / blast-radius-cap / multi-finding-batch / mixed-action-classes.                                                                                                                                                                                                                                                                                                                                                                    |
| 14   | ⬜ pending | —         | `RemediationEvalRunner` + `nexus_eval_runners` entry-point + **10/10 acceptance** via `eval-framework run --runner remediation`. Fixture parser mocks the kubectl executor + D.6 detector for deterministic eval-time validation.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 15   | ⬜ pending | —         | CLI (`remediation eval` / `remediation run`). `--mode` flag · `--findings PATH` · `--kubeconfig` / `--in-cluster` / artifact-only · `--rollback-window-sec`. Mutual-exclusion gates + mode-escalation gates surface as `click.UsageError`.                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 16   | ⬜ pending | —         | README + operator runbook (`runbooks/remediation_workflow.md`, 12 sections including the `execute` mode safety playbook, RBAC requirements for patching, rollback semantics, and the contract authorization fields). v0.1 verification record `docs/_meta/a1-verification-<date>.md`. **First "do" agent shipped; cure quadrant 1/3.**                                                                                                                                                                                                                                                                                                                          |

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
