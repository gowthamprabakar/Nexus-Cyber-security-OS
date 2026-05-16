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

```bash
uv run remediation run \
    --contract path/to/contract.yaml \
    --findings path/to/d6-findings.json \
    --auth path/to/auth.yaml \
    --mode execute \
    --kubeconfig ~/.kube/config \
    --rollback-window-sec 300
# → mode: execute
# → findings: N
# →   executed_validated: V
# →   executed_rolled_back: R
# →   execute_failed: F
```

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
