# Remediation Agent — NLAH

**A.1 — the first "do" agent in the Nexus Cyber OS platform.** Consumes OCSF findings from any detect agent and **generates + optionally executes** remediation artifacts against the live Kubernetes cluster, with safety primitives that make production action safe.

## Mission

Close the detect→cure loop. D.6 finds a misconfigured workload; A.1 generates a patch that fixes it; if the operator has authorised execution, A.1 applies the patch, waits for K8s controllers to reconcile, re-runs D.6 to verify the fix worked, and rolls the patch back if validation fails. Every step lands in a tamper-evident audit chain.

## Operational tiers

A.1 ships **three operational tiers on a single agent**, gated by safety primitives that match each mode's blast radius:

| Mode        | Action                                         | Blast radius                                 | Authorisation needed                                             |
| ----------- | ---------------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------- |
| `recommend` | Generate artifacts only; no execution          | None                                         | Default; always allowed                                          |
| `dry-run`   | `kubectl --dry-run=server`; reports diff       | None (server-side validation only)           | `mode_dry_run_authorized: true` in auth.yaml                     |
| `execute`   | Apply for real; rollback on validation failure | Single workload per artifact, capped per run | `mode_execute_authorized: true` + `authorized_actions` allowlist |

Per-run defaults to `recommend`; operators opt into higher tiers via `--mode <name>` AND a matching `auth.yaml` field. **No action class executes unless explicitly named in `authorized_actions`.**

## Seven-stage pipeline

```
INGEST → AUTHZ → GENERATE → DRY-RUN → EXECUTE → VALIDATE → ROLLBACK
```

Mode/stage matrix:

| Mode        | INGEST | AUTHZ | GENERATE | DRY-RUN | EXECUTE | VALIDATE | ROLLBACK |
| ----------- | :----: | :---: | :------: | :-----: | :-----: | :------: | :------: |
| `recommend` |   ✅   |  ✅   |    ✅    |   ❌    |   ❌    |    ❌    |    ❌    |
| `dry-run`   |   ✅   |  ✅   |    ✅    |   ✅    |   ❌    |    ❌    |    ❌    |
| `execute`   |   ✅   |  ✅   |    ✅    |   ✅    |   ✅    |    ✅    |   ✅†    |

† ROLLBACK runs only if VALIDATE returns `requires_rollback=True`.

## v0.1 action classes (5)

Each class is a pure-function pair (`build` + shared `swap_for_inverse`). All five emit K8s strategic-merge-patches:

| Source D.6 rule_id             | Action class                             | What it does                                                   |
| ------------------------------ | ---------------------------------------- | -------------------------------------------------------------- |
| `run-as-root`                  | `K8S_PATCH_RUN_AS_NON_ROOT`              | Sets `securityContext.runAsNonRoot: true` + `runAsUser: 65532` |
| `missing-resource-limits`      | `K8S_PATCH_RESOURCE_LIMITS`              | Adds `resources.limits.cpu: 500m` + `memory: 256Mi`            |
| `read-only-root-fs-missing`    | `K8S_PATCH_READ_ONLY_ROOT_FS`            | Sets `securityContext.readOnlyRootFilesystem: true`            |
| `image-pull-policy-not-always` | `K8S_PATCH_IMAGE_PULL_POLICY_ALWAYS`     | Sets `imagePullPolicy: Always`                                 |
| `allow-privilege-escalation`   | `K8S_PATCH_DISABLE_PRIVILEGE_ESCALATION` | Sets `securityContext.allowPrivilegeEscalation: false`         |

Each class also emits an **inverse patch** that returns the workload to its pre-patch state. The agent applies the inverse when post-validation fails.

**v0.2+ defers**: `privileged-container`, `host-network`, `host-pid`, `host-ipc`, `auto-mount-sa-token` (all too high blast-radius for v0.1 auto-remediation; the recommend path still generates artifacts for these).

## Safety primitives baked into v0.1

1. **Pre-authorised action allowlist** in `auth.yaml` — un-allowlisted actions are refused at Stage 2 (AUTHZ) with a `refused_unauthorized` audit entry.
2. **Mode-escalation gate** — `dry_run` and `execute` require explicit `auth.yaml` opt-in; the CLI flag alone is insufficient.
3. **Blast-radius cap** — `max_actions_per_run` (default 5, capped 50). Refusing-with-audit if a run would exceed.
4. **Mandatory dry-run before execute** — `execute` mode always runs Stage 4 first; a failed dry-run aborts before Stage 5.
5. **Rollback timer + post-validation** — `execute` mode waits `rollback_window_sec` (default 300s; capped 1800s), re-runs the D.6 detector, and auto-reverts on validation failure.
6. **Hash-chained audit per stage** — pre/post-patch SHA-256 hashes recorded; tamper-evident across the full run.
7. **Idempotency** — every artifact has a `correlation_id` derived from the source finding ID; re-running with the same input is a no-op.
8. **Workspace-scoped state** — every output file lands inside the contract's workspace dir; nothing outside.
9. **3-way cluster-access exclusion** — mirrors D.6 v0.3 (`--kubeconfig` XOR `--in-cluster` XOR artifact-only).

## Output contract

Inside the per-run charter workspace:

| File                       | Contents                                                                   |
| -------------------------- | -------------------------------------------------------------------------- |
| `findings.json`            | OCSF 2007 array of `RemediationFinding` records (one per artifact attempt) |
| `artifacts/<corr_id>.json` | Per-action kubectl-patch JSON (for operator review)                        |
| `dry_run_diffs.json`       | Server-side diff per artifact (dry-run + execute modes)                    |
| `execution_results.json`   | Per-artifact pre/post-patch state + outcome (execute mode only)            |
| `rollback_decisions.json`  | Per-artifact validate-pass/fail + rollback bool                            |
| `report.md`                | Operator-facing summary                                                    |
| `audit.jsonl`              | F.6 hash-chained chain (11 action types; every stage emits)                |

## Wire shape

A.1 is the **first producer of OCSF v1.3 `class_uid 2007` Remediation Activity** in the platform. Downstream consumers (D.7 cross-incident correlation, S.1 console replay, Meta-Harness self-evolution) subscribe to this class to learn what the platform _did_, complementing OCSF 2003 (Compliance Finding) which tells them what was _wrong_.

Finding-ID shape: `REM-<TARGET>-<NNN>-<context>` (e.g. `REM-K8S-001-runasnonroot-frontend`). Target segment is `[A-Z0-9]+` (widened from F.3's `[A-Z]+` to admit `K8S`).

## When to use which mode

- **`recommend`** — Pre-production CI/CD: generate artifacts during the PR review so operators see the proposed fixes before merging. Also: first-time runs against a new cluster (zero blast-radius bootstrap).
- **`dry-run`** — Staging: validate the patch against the live K8s admission webhooks without persisting. Useful when the operator wants confidence the patch won't be rejected before flipping to `execute`.
- **`execute`** — Production: apply the fix. The agent ships with bulletproof safety primitives (mandatory dry-run + rollback timer + post-validation) so this is safer than running `kubectl patch` by hand.

## Charter contract

A.1 runs under the standard ADR-007 charter:

- Standard budget caps (LLM calls / tokens / wall-clock / cloud-API-calls / mb-written)
- ADR-007 v1.1 (LLM adapter via `charter.llm_adapter` — plumbed but never called in v0.1)
- ADR-007 v1.2 (NLAH loader is a 21-LOC shim — **A.1 is the 7th native v1.2 agent** after D.3 / F.6 / D.7 / D.4 / D.5 / D.6)
- Not always-on (v1.3); not sub-agent-spawning (v1.4 candidate)
