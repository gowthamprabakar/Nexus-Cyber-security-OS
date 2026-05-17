# Remediation Workflow Runbook — A.1 v0.1

Operator-facing runbook for the **Remediation Agent**. Covers the safety
contract, when to use which mode, how to author the `auth.yaml`, the RBAC
required for `--mode execute`, the rollback semantics, downstream routing, and
the troubleshooting tree for the most common failures.

**Audience:** SREs and security engineers running A.1 against a real cluster.
If you are running CI scans of rendered manifests, read [Section 2](#2-mode-recommend) only.

---

## Table of contents

1. [Pre-flight — what A.1 needs from you](#1-pre-flight--what-a1-needs-from-you)
2. [`--mode recommend` — the CI/PR review surface](#2-mode-recommend)
3. [`--mode dry_run` — preview against the live cluster](#3-mode-dry_run)
4. [`--mode execute` — production action with rollback](#4-mode-execute)
5. [`auth.yaml` schema reference](#5-authyaml-schema-reference)
6. [RBAC requirements for `execute` mode](#6-rbac-requirements-for-execute-mode)
7. [Rollback semantics — the 4-case decision matrix](#7-rollback-semantics)
8. [The seven output files — what to look at when](#8-the-seven-output-files)
9. [F.6 audit log — auditing what the agent did](#9-f6-audit-log)
10. [Routing to D.7 Investigation + downstream consumers](#10-routing-to-d7-investigation)
11. [Troubleshooting — top 10 failure modes](#11-troubleshooting)
12. [Phase-1c roadmap — what's coming next](#12-phase-1c-roadmap)
13. [`promotion.yaml` schema reference (v0.1.1+)](#13-promotionyaml-schema-reference-v011)
14. [v0.1 → v0.1.1 migration](#14-v01--v011-migration)

---

## 1. Pre-flight — what A.1 needs from you

Before running A.1 in **any** mode, you need:

- **An `ExecutionContract` YAML** — the same shape every Nexus agent consumes. The agent reads `workspace`, `customer_id`, and `delegation_id` from it; writes all output files under `workspace/`.
- **A `findings.json` from a detect agent** — D.6 today (`k8s-posture run --kubeconfig … --manifest-dir …`). The agent filters the findings to those whose `rule_id` maps to a v0.1 action class (see the [5-rule table in the README](../README.md#the-five-v01-k8s-action-classes)).

For `dry_run` and `execute` modes you **additionally** need:

- **An `auth.yaml`** — explicit opt-in for the mode and an allowlist of action classes (see [Section 5](#5-authyaml-schema-reference)).
- **Cluster access** — either `--kubeconfig PATH` or `--in-cluster` (the two are mutually exclusive). For `execute` mode the credentials must have `patch` verb on the affected workload kinds (see [Section 6](#6-rbac-requirements-for-execute-mode)).

A.1's defaults are conservative: omit `--auth` and you get `recommend`-only with an empty allowlist (the safest no-op).

---

## 2. `--mode recommend`

**Use this in CI, in PR review pipelines, on developer laptops.** Generates artifacts only; **never** calls `kubectl`. Safe to run anywhere — no cluster access needed, no opt-in flags required.

```bash
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings path/to/d6-findings.json
# → mode: recommend
# → findings: N
# →   recommended_only: N
```

What you get under `workspace/`:

- `findings.json` — OCSF 2007 records, one per recommendation, outcome `recommended_only`.
- `artifacts/<correlation_id>.json` — one file per recommendation: the exact `kubectl patch` body and inverse body the agent **would** apply.
- `report.md` — the human-readable summary with per-action-class rollup.
- `audit.jsonl` — F.6 hash-chained audit log of what the agent considered.

**What to do with the output:** treat `artifacts/<corr_id>.json` like a PR diff. The operator reviews them, hand-applies in change-management, and the next D.6 scan should show the finding resolved.

---

## 3. `--mode dry_run`

**Use this as the smoke test before `execute`.** Runs `kubectl --dry-run=server` for every artifact; catches admission webhook + RBAC failures before they touch the cluster. Nothing is applied.

```bash
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode dry_run \
    --kubeconfig ~/.kube/config
# → mode: dry_run
# → findings: N
# →   dry_run_only: N   (or dry_run_failed: M if any artifact's webhook rejected it)
```

The opt-in line in `auth.yaml`:

```yaml
mode_recommend_authorized: true
mode_dry_run_authorized: true
authorized_actions:
  - remediation_k8s_patch_runAsNonRoot
  # ... whatever you want to allow
```

**What to do with the output:** read `dry_run_diffs.json` — the server-side diff per artifact, with `exit_code` and `stderr` for any that failed. A `dry_run_failed` outcome means the cluster's admission webhooks or your RBAC blocked the patch; investigate before promoting to `execute`.

---

## 4. `--mode execute`

**Production action — applies for real with mandatory post-validation + rollback.** The most dangerous tier; the most safety primitives layered in front of it.

### 4.0 Two-layer opt-in: auth.yaml AND the operational kill-switch flag

As of A.1 v0.1, `--mode execute` is **locked OFF by default at the CLI layer**, independently of whatever `auth.yaml` says. To run execute mode, **both** of the following must be true:

1. `auth.yaml` has `mode_execute_authorized: true` (the per-tenant policy gate).
2. The CLI is invoked with `--i-understand-this-applies-patches-to-the-cluster` (the operational per-invocation gate).

The operational flag is a deliberate "do you really mean it" guard. It exists because `auth.yaml` lives on disk and can be over-broad by accident; the CLI flag forces the operator to opt in **at the moment of invocation**. **Even an over-broad `auth.yaml` cannot apply patches without the flag also being supplied at the command line.** Until A.1's safety contract has been proven against a live cluster (gate G3 of the four-gate plan in the post-A.1 readiness report), the operational flag should remain unset in any environment that holds real workloads.

```bash
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode execute \
    --kubeconfig ~/.kube/config \
    --rollback-window-sec 300 \
    --i-understand-this-applies-patches-to-the-cluster
# → mode: execute
# → findings: N
# →   executed_validated: V
# →   executed_rolled_back: R
# →   execute_failed: F
```

Without the operational flag, `--mode execute` exits non-zero with a `UsageError` pointing at the flag name; nothing touches the cluster. `--mode recommend` and `--mode dry_run` are unaffected by the lockdown — use those to preview the patches first.

The opt-in line in `auth.yaml`:

```yaml
mode_recommend_authorized: true
mode_dry_run_authorized: true
mode_execute_authorized: true # explicit opt-in
authorized_actions:
  - remediation_k8s_patch_runAsNonRoot
  # ...
max_actions_per_run: 5 # hard cap; whole run refused if exceeded
rollback_window_sec: 300 # 60-1800
```

Every executed patch goes through:

1. **Stage 4: DRY-RUN** — same `kubectl --dry-run=server` as `--mode dry_run`. Any failure here aborts the patch (`dry_run_failed`).
2. **Stage 5: EXECUTE** — `kubectl patch` for real. Pre-patch SHA-256 + post-patch SHA-256 are captured for the audit chain. Any failure here is `execute_failed`.
3. **Stage 6: VALIDATE** — wait `rollback_window_sec`, re-run the D.6 detector against the affected workload, check whether the original `rule_id` is still firing.
4. **Stage 7: ROLLBACK** — if the rule is still firing, the inverse patch is applied automatically (`executed_rolled_back`). If the rule is gone, the patch is committed (`executed_validated`).

**Read [Section 7](#7-rollback-semantics) for the rollback decision matrix.** Read [Section 11](#11-troubleshooting) for what to do when something goes wrong.

---

## 5. `auth.yaml` schema reference

```yaml
# All fields optional; the defaults are the safest no-op.

mode_recommend_authorized: bool # default: true
mode_dry_run_authorized: bool # default: false
mode_execute_authorized: bool # default: false

authorized_actions: list[str] # default: []
# action_type values that the agent is allowed to build. An artifact whose
# action_type is NOT in this list is refused (outcome: refused_unauthorized).
# The valid values are the RemediationActionType enum:
#   - remediation_k8s_patch_runAsNonRoot
#   - remediation_k8s_patch_resource_limits
#   - remediation_k8s_patch_readOnlyRootFilesystem
#   - remediation_k8s_patch_imagePullPolicy_Always
#   - remediation_k8s_patch_disable_privilege_escalation

max_actions_per_run: int # default: 5; range: 1-50
# Hard blast-radius cap. The whole run is refused (outcome:
# refused_blast_radius) if the authorized finding count exceeds this. There is
# no partial-apply mode.

rollback_window_sec: int # default: 300; range: 60-1800
# How long Stage 6 waits between Stage 5's apply and the re-detection scan.
# Lower bound matches K8s controller reconcile latency; upper bound is one
# operator's-patience worth of wait. Override per-run via --rollback-window-sec.
```

Pydantic enforces every range — invalid `auth.yaml` content fails fast with a clear validation error.

---

## 6. RBAC requirements for `execute` mode

The credentials A.1 uses (either via `--kubeconfig` or via the Pod's mounted ServiceAccount token) need:

- **`patch` verb** on the workload kinds named in `authorized_actions`. All five v0.1 action classes patch the pod-spec template, so a single `patch` permission on the parent workload kind covers it.
- **`get` verb** on the same workload kinds — required by `kubectl patch --dry-run=server` (Stage 4) and by Stage 5's `fetch_state=True` (which captures the pre- and post-patch resource state for the audit chain hashes).
- **`list` verb** on the namespace scope — required by the D.6 detector re-run (Stage 6).

Example ClusterRole for a production deployment scanning the `production` namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nexus-remediation-execute
rules:
  - apiGroups: ['apps']
    resources: ['deployments', 'statefulsets', 'daemonsets', 'replicasets']
    verbs: ['get', 'list', 'patch']
  - apiGroups: ['batch']
    resources: ['jobs', 'cronjobs']
    verbs: ['get', 'list', 'patch']
  - apiGroups: ['']
    resources: ['pods']
    verbs: ['get', 'list', 'patch']
```

For an `--in-cluster` deployment, bind this ClusterRole to the Pod's ServiceAccount via a RoleBinding scoped to the namespace you intend to patch. Do **not** grant cluster-wide patch — A.1 has no need for it and the blast radius isn't worth the convenience.

---

## 7. Rollback semantics

Stage 6 + Stage 7 implement post-validation re-detection: A.1 doesn't trust the patch to have fixed the rule just because `kubectl patch` exited 0. The decision matrix:

| Stage 4 (dry-run) | Stage 5 (execute) | Stage 6 (re-detect)  | Stage 7 (rollback) | Outcome                | report.md pin |
| ----------------- | ----------------- | -------------------- | ------------------ | ---------------------- | ------------- |
| ✅ pass           | ✅ pass           | ✅ rule gone         | —                  | `executed_validated`   | —             |
| ✅ pass           | ✅ pass           | ❌ rule still firing | ✅ inverse applied | `executed_rolled_back` | **Pin 1**     |
| ✅ pass           | ❌ fail           | —                    | —                  | `execute_failed`       | **Pin 2**     |
| ❌ fail           | —                 | —                    | —                  | `dry_run_failed`       | **Pin 2**     |

**Why re-run the D.6 detector instead of inspecting the patch directly?** A K8s patch can succeed at the API layer but fail at the runtime layer — a controller webhook rejects the spec change, the Pod doesn't restart, the patch race-conditions against another writer. Only a post-validation detector pass tells us whether the _vulnerability_ is gone, not just whether the _patch_ applied. This is the gold-standard safety contract.

**Why the rollback window?** A Deployment patch propagates to its Pods on the next reconcile, which can take 10-90s. A pod-spec patch is nearly instant, but admission webhooks may add latency. The default 300s is a conservative middle ground; lower it (down to 60s) when you've measured your cluster's reconcile latency, raise it (up to 1800s) for clusters with long-tail webhook delays.

---

## 8. The seven output files

Every run writes the same seven files under `contract.workspace/`. What to look at depends on what you want to know:

| Question                                         | File                       |
| ------------------------------------------------ | -------------------------- |
| "What did the agent decide, in OCSF wire shape?" | `findings.json`            |
| "What would I read into Slack / a PR comment?"   | `report.md`                |
| "What was the exact patch for finding X?"        | `artifacts/<corr_id>.json` |
| "Why did Stage 4 fail for finding Y?"            | `dry_run_diffs.json`       |
| "What did Stage 5 actually change?"              | `execution_results.json`   |
| "Why did Stage 6 trigger a rollback?"            | `rollback_decisions.json`  |
| "Show me the full hash-chained audit"            | `audit.jsonl`              |

`report.md` uses the **dual-pin pattern**: rollbacks (`executed_rolled_back`) are pinned first, failures (`dry_run_failed` + `execute_failed`) second. The per-outcome breakdown that follows is ordered most-actionable-first.

---

## 9. F.6 audit log

A.1 emits 11 distinct action types into the F.6 hash-chained audit log:

| Action                             | When                                                            |
| ---------------------------------- | --------------------------------------------------------------- |
| `remediation.run.started`          | Stage 1 (with mode, allowlist, blast cap, rollback window)      |
| `remediation.findings.ingested`    | Stage 1 done (with count + source path)                         |
| `remediation.action.refused`       | Stage 2, one per refused finding (with reason)                  |
| `remediation.blast_radius.refused` | Stage 2, once if the cap is exceeded                            |
| `remediation.artifact.generated`   | Stage 3, one per generated artifact                             |
| `remediation.dry_run.completed`    | Stage 4, with `exit_code` + pre/post hashes (when applicable)   |
| `remediation.execute.completed`    | Stage 5 success path                                            |
| `remediation.execute.failed`       | Stage 5 failure path                                            |
| `remediation.validate.completed`   | Stage 6, with `requires_rollback` flag + matched-findings count |
| `remediation.rollback.completed`   | Stage 7, with `exit_code` of the inverse patch                  |
| `remediation.run.completed`        | End, with per-outcome counts + total                            |

Every entry carries the run's `correlation_id` so cross-referencing OCSF 2007 records to audit entries is just a string match. Tail hash + head hash are pinned at the bottom of `report.md`; use them as the tamper-evident chain proof.

Query the audit log directly:

```bash
uv run audit-agent query --workspace path/to/workspace --filter 'remediation.*'
```

---

## 10. Routing to D.7 Investigation

A.1's `findings.json` is wire-compatible with the fabric routing layer. D.7 Investigation already filters on OCSF `class_uid 2007` events (Phase-1b shipped that subscription), so once the run completes, D.7 picks up the records on the next cycle. No additional config required.

Common downstream patterns:

- **D.7 investigates an `executed_rolled_back` outcome** — the rule still fires after the patch, meaning either the action class is too narrow for that workload or there's an admission webhook re-mutating the spec. D.7's "patch-failure investigation" template walks both.
- **F.6 dashboards key on `remediation.run.completed`** — the per-outcome counts in that audit entry feed the cure-quadrant compliance dashboard.
- **F.4 tenant isolation** — every OCSF 2007 record carries the customer_id from the contract; F.4's RLS policies route findings by tenant without A.1 needing to know about multi-tenancy.

---

## 11. Troubleshooting

**`AuthorizationError: mode='dry_run' not authorized`** — your `auth.yaml` doesn't set `mode_dry_run_authorized: true`. The CLI re-raises this as a `click.UsageError` so the message includes the exact field name to add.

**Outcome `refused_unauthorized` on a finding you expected to remediate** — check that the action class is in `authorized_actions`. The mapping is in the [README's 5-rule table](../README.md#the-five-v01-k8s-action-classes); the action class name is the `RemediationActionType` enum value (e.g. `remediation_k8s_patch_runAsNonRoot`).

**Outcome `refused_blast_radius`** — the authorized finding count exceeded `max_actions_per_run`. A.1 refuses the whole run rather than partially applying. Raise the cap (max 50) or narrow the input findings.

**Outcome `dry_run_failed`** — `kubectl --dry-run=server` rejected the patch. Read the `stderr_head` field of the matching record in `dry_run_diffs.json`. Common causes: admission webhook rejected the spec, RBAC missing `patch` verb, the workload kind doesn't support the action class's strategic-merge-patch shape (rare; the v0.1 action classes are all Deployment/StatefulSet/DaemonSet-tested).

**Outcome `execute_failed` on a patch that passed dry-run** — race condition with another writer (HPA, GitOps controller, another operator). Wait for the other writer's reconcile, re-ingest D.6, re-run A.1. The `correlation_id` is idempotent: a re-run on the same `(namespace, workload, container, rule_context)` produces the same artifact.

**Outcome `executed_rolled_back` on a patch that should have fixed the rule** — the patch applied at the API layer but the runtime didn't honor it. Read `rollback_decisions.json` for the matched-findings count after the rollback window. Common causes: a mutating admission webhook (Linkerd, Istio, OPA Gatekeeper) is re-mutating the spec; the controller didn't reconcile within the rollback window (raise `--rollback-window-sec`); the workload has a Pod-disruption-budget blocking the rolling update.

**No `findings.json` from D.6 to feed in** — run D.6 first: `k8s-posture run --contract … --kubeconfig … --manifest-dir …`. A.1 expects `findings.json` at the path given to `--findings`; the file must be in D.6's OCSF 2003 wrapped wire shape (the `findings_reader.py` is source-strict — only `evidence.kind == "manifest"` records are admitted).

**`click.UsageError: --kubeconfig and --in-cluster are mutually exclusive`** — pick one. `--kubeconfig` is for laptops and CI workers with kubeconfig files on disk; `--in-cluster` is for the production CronJob deployment running inside the cluster with a mounted SA token.

**`click.UsageError: --mode dry_run requires cluster access`** — non-recommend modes need `--kubeconfig` or `--in-cluster`. `--mode recommend` is the only mode that runs without cluster access.

**`click.UsageError: Invalid value for '--rollback-window-sec'`** — the value must be in `[60, 1800]`. Below 60s is too short for K8s controller reconcile; above 1800s is too long to wait for a re-detect.

---

## 12. Phase-1c roadmap

A.1 v0.1 ships the five smallest-blast-radius K8s action classes. The Phase-1c agenda expands the action universe along two axes:

- **More K8s action classes** — adding `k8s-patch-host-network-removal`, `k8s-patch-auto-mount-sa-token`, `k8s-patch-privileged-container-removal`. Each follows the same `(build, inverse)` pair pattern; the `validator.py` re-detection contract doesn't change.
- **AWS Cloud Custodian actions** — A.1 v0.2 will ingest F.3 cloud-posture findings and emit Cloud Custodian policy artifacts (S3-public-access-block, IAM least-privilege, encryption-at-rest). Same OCSF 2007 wire shape; same 7-stage pipeline; the executor swaps from `kubectl` to `boto3` / Cloud Custodian's policy engine.

Both expansions reuse the v0.1 safety primitives unchanged. The opt-in / allowlist / blast-cap / dry-run / rollback discipline is the cure-quadrant's load-bearing contract.

---

## 13. `promotion.yaml` schema reference (v0.1.1+)

The earned-autonomy pipeline lives in `promotion.yaml`. The file is a **per-cluster, per-environment cache** of each action class's current graduation stage + accumulated evidence + the sign-off history that justified the most-recent stage transition. The F.6 audit chain at `audit.jsonl` is the **source of truth**; `promotion.yaml` is the operator-readable derived view.

### Top-level shape

```yaml
schema_version: '0.1' # pinned; bumping is a separate migration
cluster_id: prod-eu-1 # operator-supplied label, propagated into audit events
created_at: '2026-05-17T00:00:00Z' # UTC; set by `remediation promotion init`
last_modified_at: '2026-05-17T00:00:00Z' # UTC; updated atomically by every save (>= created_at)
action_classes: # dict keyed by `RemediationActionType.value`
  remediation_k8s_patch_runAsNonRoot:
    action_type: remediation_k8s_patch_runAsNonRoot
    stage: 2
    sign_offs:
      - event_kind: advance
        operator: alice
        timestamp: '2026-05-17T09:00:00Z'
        reason: 'graduated runAsNonRoot 1->2 after 7 successful dry-runs across prod'
        from_stage: 1
        to_stage: 2
    evidence:
      stage1_artifacts: 12
      stage2_dry_runs: 7
      stage3_executes: 0
      stage3_consecutive_executes: 0
      stage3_unexpected_rollbacks: 0
      stage3_distinct_workloads: []
```

### Stage semantics

| Stage | Effective max mode for the action class | Required sign-off chain                                                                                                                                                                                                  |
| ----- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1     | `recommend`                             | None (the floor; absent action classes are implicitly Stage 1)                                                                                                                                                           |
| 2     | `dry_run`                               | `advance(1→2)` last                                                                                                                                                                                                      |
| 3     | `execute`                               | `advance(1→2)` then `advance(2→3)` (chronological)                                                                                                                                                                       |
| 4     | `execute` (unattended)                  | **Globally closed in code.** CLI refuses any `advance` or `reconcile` that would land Stage 4 until the rolled-back-path mutating-admission-webhook fixture lands AND ≥4 weeks of customer Stage-3 evidence accumulates. |

The pre-flight gate inside `agent.run()` reads `tracker.stage_for(action_type)` and computes `effective_mode = min(operator_requested_mode, stage_max_for_stage(stage))`. When **all** authorised artifacts would be downgraded and `operator_requested_mode != recommend`, the gate emits `REFUSED_PROMOTION_GATE` for each finding (zero kubectl contact). When **some** artifacts would be downgraded, the run proceeds per-finding at each artifact's effective mode (one finding becomes `RECOMMENDED_ONLY`, another `DRY_RUN_ONLY`, another `EXECUTED_VALIDATED` in the same run).

### Evidence counters

| Counter                       | Increments on                                                      | Read by                                                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `stage1_artifacts`            | Every successful Stage-1 artifact emission                         | `propose_promotions()` — threshold ≥1 → propose Stage 1 → 2 (operator confirms manually)                                                            |
| `stage2_dry_runs`             | Every successful Stage-2 `kubectl --dry-run=server` (exit 0)       | `propose_promotions()` — threshold ≥5 → propose Stage 2 → 3                                                                                         |
| `stage3_executes`             | Every successful `executed_validated` outcome at Stage 3           | Informational                                                                                                                                       |
| `stage3_consecutive_executes` | As `stage3_executes`, but resets to 0 on every unexpected rollback | `propose_promotions()` — threshold ≥30 (in combination with distinct ≥10) → propose Stage 3 → 4 (but Stage 4 is globally closed in code, see above) |
| `stage3_unexpected_rollbacks` | Every `executed_rolled_back` outcome NOT attributed to a webhook   | Operator review surface; resets `stage3_consecutive_executes`                                                                                       |
| `stage3_distinct_workloads`   | List of `"<namespace>/<workload_name>"` pairs touched at Stage 3   | `propose_promotions()` — threshold ≥10 distinct pairs for Stage 3 → 4                                                                               |

### Audit event vocabulary (9 actions, prefix `promotion.`)

| Action                                   | Emitted by                                              | Carries                                                               |
| ---------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------- |
| `promotion.evidence.stage1`              | `agent.run()` on each Stage-1 artifact                  | `action_type`                                                         |
| `promotion.evidence.stage2`              | `agent.run()` on each successful dry_run                | `action_type`                                                         |
| `promotion.evidence.stage3`              | `agent.run()` on each `executed_validated`              | `action_type`, `namespace`, `workload_name`                           |
| `promotion.evidence.unexpected_rollback` | `agent.run()` on each unexpected `executed_rolled_back` | `action_type`                                                         |
| `promotion.advance.proposed`             | `tracker.propose_promotions()` (informational)          | `action_type`, `from_stage`, `to_stage`, `reason`, `evidence_summary` |
| `promotion.advance.applied`              | `remediation promotion advance` CLI                     | `action_type`, `signoff` payload                                      |
| `promotion.demote.applied`               | `remediation promotion demote` CLI                      | `action_type`, `signoff` payload                                      |
| `promotion.init.applied`                 | `remediation promotion init` CLI                        | `cluster_id`, optional list of pre-seeded `action_classes`            |
| `promotion.reconcile.completed`          | `remediation promotion reconcile` CLI                   | `chain_entries_replayed`, optional `refused: true` + `refusal_reason` |

### Reconcile from chain — known limitation

`remediation promotion reconcile --audit <chain> --promotion <path>` replays the audit chain into a fresh `PromotionFile`. **Limitation:** if the chain contains only `promotion.evidence.*` events (no `advance` / `demote` / `init` events — which is what `agent.run()` alone emits), `replay()` cannot reconstruct **stage** or **sign_offs** above Stage 1. It reconstructs **evidence counters** field-by-field exactly.

Practical implication: to reconstruct `promotion.yaml` end-to-end from the chain, the chain must contain the full CLI history (`promotion init` once, every `advance` / `demote` ever issued). A chain containing only agent runs replays to a Stage-1, evidence-only file regardless of what stage the operator has graduated the action class to. Reconcile is therefore a **safety net** for restoring evidence counters and detecting drift, not a full restore-from-backup mechanism.

### File location convention

By convention `promotion.yaml` lives at `<persistent_root>/promotion.yaml`, where `persistent_root` is the ExecutionContract field operators already supply for cross-run state. Operators are free to put it anywhere — every `remediation promotion` subcommand takes an explicit `--promotion <path>`. The agent's run-time `agent.run(promotion=...)` API takes a `PromotionTracker` instance directly; the CLI's `remediation run` subcommand does **not** yet wire a `--promotion` flag (v0.1.2 task — see [§14](#14-v01--v011-migration) below).

---

## 14. v0.1 → v0.1.1 migration

**For an operator currently running `remediation run --mode execute` on v0.1, with no prior knowledge of the promotion system. Every step is concrete; no "configure appropriately" hand-waving.**

### What changes for you on day 1 of v0.1.1

| Surface                                                                                                                                                          | Behaviour change                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your existing `remediation run --contract X --findings Y --auth Z --mode execute --kubeconfig … --i-understand-this-applies-patches-to-the-cluster` command line | **None.** v0.1.1 ships the promotion package additively. Your existing v0.1 CLI invocation works unchanged; `auth.yaml` + `--i-understand-…` remain your two operator-facing kill switches.                                                                                                    |
| Eval gate (if you run `remediation eval`)                                                                                                                        | "10/10 passed" → "15/15 passed". The five new cases (011–015) exercise the promotion-gate surface against the v0.1.1 parser.                                                                                                                                                                   |
| Outcome vocabulary in `report.md` / `findings.json`                                                                                                              | New value: `refused_promotion_gate`. Only appears if a `PromotionTracker` is passed to `agent.run(promotion=...)`. **The `remediation run` CLI does not pass one** today (v0.1.2 will), so v0.1.1 users running the CLI never see this outcome.                                                |
| Stage 4 (`unattended execute`)                                                                                                                                   | **Globally closed in code.** Both `remediation promotion advance --to stage_4` and `remediation promotion reconcile` refuse with the same prerequisite message naming the rolled-back-path webhook fixture + ≥4 weeks customer Stage-3 evidence. There is no flag or operator that opens this. |

**The migration below is opt-in.** You can keep running v0.1.1 exactly the way you ran v0.1 and lose nothing. Following the steps below buys you (a) operator-readable graduation tracking, (b) the `remediation promotion status` print, and (c) the foundation for the v0.1.2 CLI-gate wiring.

### Step-by-step setup

#### Step 1 — Pick a `cluster_id`

`cluster_id` is a label that identifies which cluster `promotion.yaml` is tracking. It is operator-supplied, free-form, and propagated into every `promotion.*` audit event. Use a name that's stable across re-clones of the repo: e.g., `prod-eu-1`, `staging-us-west`, `customer-acme-prod`.

```bash
export NEXUS_CLUSTER_ID=prod-eu-1
```

#### Step 2 — Decide where `promotion.yaml` and `audit.jsonl` will live

`promotion.yaml` is the operator-readable cache. `audit.jsonl` is the F.6 hash-chained log that records every `promotion.*` event for that cluster — every `remediation promotion` invocation appends to it, and `reconcile` reads it to rebuild `promotion.yaml`.

By convention, both live alongside the other per-environment state (the contract's `persistent_root`). Example: if your contract has `persistent_root: /var/lib/nexus-remediation/state`, place them at `/var/lib/nexus-remediation/state/promotion.yaml` and `/var/lib/nexus-remediation/state/promotion-audit.jsonl`. On a laptop, `~/.nexus-remediation/promotion-${NEXUS_CLUSTER_ID}.yaml` and `~/.nexus-remediation/promotion-${NEXUS_CLUSTER_ID}.jsonl` are fine.

```bash
export PROMOTION_FILE=/var/lib/nexus-remediation/state/promotion.yaml
export PROMOTION_AUDIT=/var/lib/nexus-remediation/state/promotion-audit.jsonl
```

#### Step 3 — Initialise the file

```bash
uv run remediation promotion init \
    --promotion "$PROMOTION_FILE" \
    --audit "$PROMOTION_AUDIT" \
    --cluster-id "$NEXUS_CLUSTER_ID"
```

This creates `promotion.yaml` with `schema_version: '0.1'`, your `cluster_id`, current timestamps, and **every v0.1 action class pre-registered at Stage 1** (`remediation_k8s_patch_runAsNonRoot`, `…_resource_limits`, `…_readOnlyRootFilesystem`, `…_imagePullPolicy_Always`, `…_disable_privilege_escalation`). It also appends a `promotion.init.applied` entry to `audit.jsonl`. **Every action class is at Stage 1.** No execute-mode mutation is possible from this state via the gate.

If you only want a subset of action classes registered (the rest still effectively at Stage 1 via the safe-by-default semantic), pass `--action-class` per class:

```bash
uv run remediation promotion init \
    --promotion "$PROMOTION_FILE" \
    --audit "$PROMOTION_AUDIT" \
    --cluster-id "$NEXUS_CLUSTER_ID" \
    --action-class remediation_k8s_patch_runAsNonRoot \
    --action-class remediation_k8s_patch_resource_limits
```

`init` refuses to overwrite an existing `promotion.yaml`. If you need to start over, either move the existing file aside (`mv promotion.yaml promotion.yaml.bak`) or use `remediation promotion reconcile` to rebuild from the audit chain.

Verify:

```bash
uv run remediation promotion status --promotion "$PROMOTION_FILE"
```

Expected output (verbatim shape — five rows for the five action classes, all at `STAGE_1`):

```
cluster_id:       prod-eu-1
schema_version:   0.1
last_modified_at: 2026-05-17T...Z

action_class                                            stage      evidence
--------------------------------------------------------------------------------------------------------------
remediation_k8s_patch_runAsNonRoot                      STAGE_1    s1=0 s2=0 s3=0 consec=0 rb=0 workloads=0
remediation_k8s_patch_resource_limits                   STAGE_1    s1=0 s2=0 s3=0 consec=0 rb=0 workloads=0
remediation_k8s_patch_readOnlyRootFilesystem            STAGE_1    s1=0 s2=0 s3=0 consec=0 rb=0 workloads=0
remediation_k8s_patch_imagePullPolicy_Always            STAGE_1    s1=0 s2=0 s3=0 consec=0 rb=0 workloads=0
remediation_k8s_patch_disable_privilege_escalation      STAGE_1    s1=0 s2=0 s3=0 consec=0 rb=0 workloads=0
```

(`s1` / `s2` / `s3` are the evidence counters from [§13](#13-promotionyaml-schema-reference-v011): Stage-1 artifacts emitted, Stage-2 successful dry-runs, Stage-3 successful validated executes. `consec` is consecutive Stage-3 successes since the last unexpected rollback. `rb` is unexpected rollbacks. `workloads` is the distinct count of `<namespace>/<workload>` pairs touched at Stage 3.)

#### Step 4 — Establish an operator identifier

Every promotion event in the audit chain records the operator who issued it. Resolution order: `--operator <NAME>` (always wins) → `$NEXUS_OPERATOR` → `$USER` → `unknown`.

Pick the convention you want. For a single operator: `export NEXUS_OPERATOR="alice@acme.com"` once and forget. For multi-operator: each operator passes `--operator` on every command.

#### Step 5 — Decide your starting graduations

For each of the **five v0.1 action classes** in [the README's table](../README.md#the-five-v01-k8s-action-classes), decide the starting stage based on **what you've already verified against this cluster in v0.1 operation**:

| Action class                                         | Start at Stage 1 if…                                     | Start at Stage 2 if…                                     | Start at Stage 3 if…                                                                                        |
| ---------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `remediation_k8s_patch_runAsNonRoot`                 | You've never applied A.1's runAsNonRoot artifact by hand | You've applied ≥1 successfully, by hand, on this cluster | You've executed A.1's `--mode execute` ≥10 times on this cluster's workloads with zero unexpected rollbacks |
| `remediation_k8s_patch_resource_limits`              | Same                                                     | Same                                                     | Same                                                                                                        |
| `remediation_k8s_patch_readOnlyRootFilesystem`       | Same                                                     | Same                                                     | Same                                                                                                        |
| `remediation_k8s_patch_imagePullPolicy_Always`       | Same                                                     | Same                                                     | Same                                                                                                        |
| `remediation_k8s_patch_disable_privilege_escalation` | Same                                                     | Same                                                     | Same                                                                                                        |

**The conservative answer is Stage 1 for everything.** A.1 v0.1.1 does not require you to back-date evidence — you can start at Stage 1 today and let the operational record build up.

#### Step 6 — Issue the `advance` commands for everything above Stage 1

`advance` must move exactly one stage at a time. To get from Stage 1 to Stage 3, you issue two commands.

```bash
# Example: graduate runAsNonRoot to Stage 2 based on prior v0.1 manual-apply evidence
uv run remediation promotion advance \
    --promotion "$PROMOTION_FILE" \
    --audit "$PROMOTION_AUDIT" \
    --action remediation_k8s_patch_runAsNonRoot \
    --to stage_2 \
    --operator "$NEXUS_OPERATOR" \
    --reason 'pre-v0.1.1 evidence: hand-applied to api-server-deployment on 2026-05-10; no rollback'

# To go further: issue stage_3 NEXT (separate command)
uv run remediation promotion advance \
    --promotion "$PROMOTION_FILE" \
    --audit "$PROMOTION_AUDIT" \
    --action remediation_k8s_patch_runAsNonRoot \
    --to stage_3 \
    --operator "$NEXUS_OPERATOR" \
    --reason 'pre-v0.1.1 evidence: executed --mode execute 12 times on prod since 2026-04-15'
```

**The CLI rejects:**

- Skip transitions (`stage_1 → stage_3` in one command). You must go via `stage_2`.
- Stage 4 (`--to stage_4`). The CLI prints the two prerequisites (rolled-back-path webhook fixture + ≥4 weeks customer Stage-3 evidence) and exits non-zero. This is the global Stage-4 closure and cannot be overridden.
- No-op transitions (advancing to the stage the action class is already at).

`--reason` is required; the text is recorded in the chain and surfaced by `remediation promotion status`. Conventional content: the empirical justification ("12 hand-applies on prod without issue") or the policy decision ("change-management ticket CR-2026-04-12 approved this").

#### Step 7 — Verify your starting state

```bash
uv run remediation promotion status --promotion "$PROMOTION_FILE"
```

The print shows every action class you've graduated, its current stage, the sign-off chain (operator + reason for each transition), and any proposals from `tracker.propose_promotions()`.

#### Step 8 — Continue running `remediation run` exactly as before

There is no `--promotion` flag on `remediation run` in v0.1.1 — the `agent.run()` Python API enforces the pre-flight gate, but the CLI does not yet wire `promotion.yaml` into the run. That wiring is **v0.1.2**, gated on the rolled-back-path webhook fixture landing first.

In the meantime: your `remediation run --mode execute` command line is unchanged from v0.1; the existing `auth.yaml` + `--i-understand-…` operational flag are the operator-facing kill switches; **`promotion.yaml` records intent for the v0.1.2 wiring, not enforcement today.**

#### Step 9 — Use `propose` + `reconcile` as needed

`tracker.propose_promotions()` returns `(action_type, from_stage, to_stage, reason, evidence_summary)` tuples for any action class whose accumulated evidence meets the next-stage threshold. The proposal is informational; the operator reviews the evidence summary and either applies (`remediation promotion advance`) or ignores. Proposals do NOT auto-advance under any circumstance.

If `promotion.yaml` ever gets out of sync with `audit.jsonl` (e.g., the file was edited by hand, or restored from an old backup), use `reconcile`:

```bash
uv run remediation promotion reconcile \
    --promotion "$PROMOTION_FILE" \
    --audit "$PROMOTION_AUDIT" \
    --cluster-id "$NEXUS_CLUSTER_ID" \
    --dry-run                              # prints the diff; omit --dry-run to apply
```

The dry-run diff shows what `--no-dry-run` would change. Both invocations refuse if the replayed state would land Stage 4 (same global closure as `advance`).

**Limitation of reconcile (load-bearing — read this):** `reconcile` replays the audit chain. If the chain contains only `promotion.evidence.*` events (the agent's run-time output) and no `promotion.advance.applied` / `promotion.init.applied` events (which come from THIS CLI's `init` / `advance` / `demote` invocations), `reconcile` reconstructs **evidence counters** but **cannot recover stage or sign_offs above Stage 1.**

Practical implication: if you bootstrap the audit chain from agent runs only (without ever running `remediation promotion init` / `advance`), then `reconcile` will reset your `promotion.yaml` to "every action class at Stage 1, evidence counters preserved." This is intentional — the chain is the source of truth; the chain didn't see the graduations because you never issued them.

To make `reconcile` losslessly restore your `promotion.yaml`: **always issue `init` once when you start tracking a cluster, and always issue `advance` / `demote` via the CLI (never by hand-editing `promotion.yaml`).** That way every event lands in the chain and the chain replays cleanly.

#### Step 10 — Plan for the rolled-back-path fixture landing

After this fixture lands (the immediate next-plan gate after v0.1.1):

1. `test_execute_rolled_back_against_live_cluster` flips from `xfail` to `pass` in the `NEXUS_LIVE_K8S=1` lane.
2. The Stage-4 prerequisite list updates in the safety-verification record.
3. v0.1.2 wires `--promotion <path>` into `remediation run` so the CLI itself enforces the gate.

The `promotion.yaml` you set up in steps 1–7 above is exactly what v0.1.2 will read.

### What if I get stuck

| Symptom                                                                                 | Fix                                                                                                       |
| --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `init` says "file already exists"                                                       | Move the existing file aside (`mv promotion.yaml promotion.yaml.bak`); re-run `init`.                     |
| `advance --to stage_4` exits non-zero                                                   | Working as intended. Stage 4 is globally closed. Read the printed message for the two prerequisites.      |
| `advance` says "no-op transition"                                                       | The action class is already at the target stage. Run `status` to confirm; nothing to do.                  |
| `advance --to stage_3` says "skip transition"                                           | The action class is at Stage 1. You must `advance --to stage_2` first, then `advance --to stage_3`.       |
| `status` shows different `evidence` counters than what your audit chain has             | Run `reconcile --dry-run` to see the diff. Re-issue any missing `advance` events (see Step 9 limitation). |
| `status` shows `proposed_promotions` for an action class you don't want to graduate yet | Ignore. Proposals never auto-advance.                                                                     |
| `remediation run --mode execute` succeeds even though I have Stage 1 in promotion.yaml  | Working as intended for v0.1.1 — the CLI `run` does not yet wire `promotion.yaml`. Wait for v0.1.2.       |

### Why this migration is opt-in and not flag-day

A flag-day migration would require every v0.1 customer to issue `init` + N×`advance` before their next `remediation run --mode execute` would work. v0.1.1 instead lets customers keep running v0.1's CLI surface unchanged, opt into promotion tracking when they're ready, and absorb v0.1.2's CLI-gate wiring when the rolled-back-path fixture lands. The earned-autonomy contract still applies — Stage 4 is globally closed in code, customer-side prerequisites of [safety-verification §6](../../../../docs/_meta/a1-safety-verification-2026-05-16.md#customer-side-prerequisites) still apply for Stage 3 enablement — but the migration cost is paid when the customer chooses to pay it, not on the v0.1.1 upgrade.
