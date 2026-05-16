# Example 2 — `dry-run` mode (staging pre-flight)

## Scenario

The platform team wants to validate that A.1's proposed patches will be accepted by the staging cluster's admission webhooks before promoting them to production. Operators have allowlisted two action classes for dry-run, but kept `execute` mode locked.

**Blast radius**: zero on the staging cluster. `kubectl --dry-run=server` validates the patch against admission webhooks + the OpenAPI schema; nothing persists.

## Inputs

`auth.yaml`:

```yaml
mode_recommend_authorized: true
mode_dry_run_authorized: true
mode_execute_authorized: false # explicitly locked
authorized_actions:
  - remediation_k8s_patch_runAsNonRoot
  - remediation_k8s_patch_resource_limits
max_actions_per_run: 5
rollback_window_sec: 300
```

D.6's `findings.json` carries 4 findings on the `staging` namespace.

## Invocation

```bash
uv run remediation run \
    --contract /tmp/contract.yaml \
    --findings /workspaces/cust_acme/k8s_posture/.../findings.json \
    --mode dry-run \
    --kubeconfig ~/.kube/config-staging \
    --cluster-namespace staging \
    --auth /tmp/auth.yaml
```

## Stage trace

1. **INGEST** — 4 ManifestFindings loaded.
2. **AUTHZ** — `filter_authorized_findings`:
   - 2 `run-as-root` findings → authorized.
   - 1 `missing-resource-limits` finding → authorized.
   - 1 `read-only-root-fs-missing` finding → refused (action class exists but not in allowlist).
   - Result: 3 authorized, 1 refused.
   - `enforce_blast_radius(3, cap=5)` → passes.
3. **GENERATE** — 3 RemediationArtifacts emitted with deterministic correlation_ids.
4. **DRY-RUN** — for each artifact, `apply_patch(dry_run=True)`:
   - kubectl runs with `--dry-run=server`. The staging cluster's admission webhooks validate.
   - 2 succeed (the runAsNonRoot patches). 1 fails (the resource-limits patch trips a custom OPA Gatekeeper constraint requiring memory ≥ 512Mi; A.1's default is 256Mi).
     5-7. **Skipped** (dry-run mode never executes for real).

## Outputs

`audit.jsonl`:

```
remediation.run_started        {mode: dry-run, ...}
remediation.findings_ingested  {count: 4, ...}
remediation.action_refused     {rule_id: read-only-root-fs-missing, reason: "not in authorized_actions allowlist"}
remediation.artifact_generated {correlation_id: corr-1, action_type: ...runAsNonRoot, ...}
remediation.artifact_generated {correlation_id: corr-2, action_type: ...runAsNonRoot, ...}
remediation.artifact_generated {correlation_id: corr-3, action_type: ...resource_limits, ...}
remediation.dry_run_completed  {correlation_id: corr-1, outcome: dry_run_only, succeeded: true}
remediation.dry_run_completed  {correlation_id: corr-2, outcome: dry_run_only, succeeded: true}
remediation.dry_run_completed  {correlation_id: corr-3, outcome: dry_run_failed, succeeded: false,
                                stderr_head: "admission webhook denied: memory limit < 512Mi"}
remediation.run_completed      {outcome_counts: {dry_run_only: 2, dry_run_failed: 1,
                                refused_unauthorized: 1}, total_actions: 4}
```

`findings.json`: 3 OCSF 2007 records (the refused one too — operators see refusals in OCSF, not just audit). `report.md`: per-outcome summary; the failed dry-run gets pinned for operator attention.

## What the operator does next

The dry-run output shows the resource-limits patch needs tuning before it can run in `execute` mode. The platform team has two options:

1. **Override the default** by extending A.1 v0.2 to read `auth.yaml`-level overrides for the default CPU/memory values.
2. **Apply the runAsNonRoot patches in execute mode** (those succeeded in dry-run) and skip resource-limits until the OPA constraint is resolved.

The two `dry_run_only` outcomes are the **green light** for flipping `mode_execute_authorized: true` for those specific action classes.

## Why this matters

`dry-run` is the **trust-building path** to `execute`. Operators learn whether the platform's defaults actually work against their cluster's policy stack (admission webhooks, OPA Gatekeeper, Pod Security Standards) before any patch lands. The audit trail of dry-runs becomes the evidence record the platform team shows the security team to unlock `execute` authorization.
