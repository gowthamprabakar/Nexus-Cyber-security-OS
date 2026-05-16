# Example 3 — `execute` mode with validation + rollback

## Scenario

Production cluster. The security team has authorised `execute` mode for two action classes after weeks of `dry-run` evidence. The agent runs as a CronJob inside the cluster (v0.3 in-cluster mode) every 6 hours; it consumes the most recent D.6 findings.json from a shared volume.

This run sees two findings. One patches cleanly. The other applies but the post-validation re-detection sees the rule_id still firing — A.1 auto-rolls back.

## Inputs

`auth.yaml` mounted as a ConfigMap:

```yaml
mode_recommend_authorized: true
mode_dry_run_authorized: true
mode_execute_authorized: true # production-ready after dry-run history
authorized_actions:
  - remediation_k8s_patch_runAsNonRoot
  - remediation_k8s_patch_imagePullPolicy_Always
max_actions_per_run: 5
rollback_window_sec: 300 # 5-minute window — gives Deployment controllers time to reconcile
```

CronJob spec (abridged):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nexus-remediation
spec:
  schedule: '0 */6 * * *'
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: nexus-remediation
          containers:
            - name: agent
              image: ghcr.io/your-org/nexus-remediation:0.1.0
              args:
                - run
                - --contract
                - /etc/nexus/contract.yaml
                - --findings
                - /shared/k8s-posture/findings.json
                - --mode
                - execute
                - --in-cluster
                - --auth
                - /etc/nexus/auth.yaml
```

D.6's `findings.json` carries 2 findings:

- A: `run-as-root` on `production/Deployment/api` container `api`
- B: `run-as-root` on `production/Deployment/legacy` container `legacy`

## Stage trace

1. **INGEST** — 2 ManifestFindings loaded.
2. **AUTHZ** — both authorized (`run-as-root` → `K8S_PATCH_RUN_AS_NON_ROOT` ∈ allowlist). Blast cap (5) not exceeded.
3. **GENERATE** — 2 RemediationArtifacts emitted.
4. **DRY-RUN** — both pass `kubectl --dry-run=server`.
5. **EXECUTE** — `kubectl patch` applied to both. Pre/post-patch SHA-256 hashes captured.
6. **VALIDATE** — wait 300s; re-run D.6 against `production` namespace; check both workloads.
   - **A (`api`)**: D.6 sees no `run-as-root` on `production/Deployment/api/api`. Patch worked. → `executed_validated`.
   - **B (`legacy`)**: D.6 still sees `run-as-root` on `production/Deployment/legacy/legacy`. (Reason discoverable from the manifest: there's a pod-spec-level `runAsUser: 0` that overrides the container-level `runAsNonRoot: true` we added.) → `requires_rollback`.
7. **ROLLBACK** — for B only: apply inverse_patch_body (removes the `runAsNonRoot` + `runAsUser` fields the agent added). Post-rollback hash recorded.

## Outputs

`audit.jsonl` (11 entries):

```
remediation.run_started        {mode: execute, authorized_actions: [...], ...}
remediation.findings_ingested  {count: 2}
remediation.artifact_generated {correlation_id: corr-A, ...}
remediation.artifact_generated {correlation_id: corr-B, ...}
remediation.dry_run_completed  {correlation_id: corr-A, outcome: dry_run_only, succeeded: true}
remediation.dry_run_completed  {correlation_id: corr-B, outcome: dry_run_only, succeeded: true}
remediation.execute_completed  {correlation_id: corr-A, pre_patch_hash: ..., post_patch_hash: ...}
remediation.execute_completed  {correlation_id: corr-B, pre_patch_hash: ..., post_patch_hash: ...}
remediation.validate_completed {correlation_id: corr-A, outcome: executed_validated, requires_rollback: false}
remediation.validate_completed {correlation_id: corr-B, outcome: executed_rolled_back, requires_rollback: true,
                                matched_findings_count: 1}
remediation.rollback_completed {correlation_id: corr-B, succeeded: true, post_patch_hash: <inverse_state>}
remediation.run_completed      {outcome_counts: {executed_validated: 1, executed_rolled_back: 1},
                                total_actions: 2}
```

`findings.json` — 2 OCSF 2007 records:

- A: outcome `executed_validated`; INFO severity (success is informational).
- B: outcome `executed_rolled_back`; MEDIUM severity (operator should investigate the pod-spec override).

`report.md` summary (the dual-pin pattern from D.6 / D.5 / F.3 — operator-facing):

```markdown
# Remediation Report

- Mode: execute
- Total actions: 2

## Per-outcome breakdown

- **executed_validated**: 1
- **executed_rolled_back**: 1

## Pinned: rollbacks (1)

- corr-B / K8S_PATCH_RUN_AS_NON_ROOT on production/Deployment/legacy/legacy
  Reason: detector still sees run-as-root after rollback window.
  Inverse applied; workload returned to pre-patch state.
  Investigate the pod-spec-level runAsUser override.

## Successes

- corr-A / K8S_PATCH_RUN_AS_NON_ROOT on production/Deployment/api/api → validated
```

## What the operator does next

- **For A**: nothing — the platform fixed it. The audit trail proves what happened; D.7 Investigation can correlate this remediation back to the original D.6 finding.
- **For B**: investigate the pod-spec-level `runAsUser: 0`. Either:
  - Add a pod-spec patch action class in A.1 v0.2 (current v0.1 is container-level only).
  - Hand-edit the `legacy` Deployment to remove the override, then re-run.

## Why this matters

Production execution with auto-rollback is **the differentiating capability** of A.1 vs Wiz (which doesn't remediate) and vs Palo Alto AgentiX (which requires per-action approval). The full stack — dry-run gate + execute + post-validation + auto-rollback + hash-chained audit — runs without human intervention for the validated cases and gracefully reverses itself for the failed ones. **No half-applied state. No silent failures.**
