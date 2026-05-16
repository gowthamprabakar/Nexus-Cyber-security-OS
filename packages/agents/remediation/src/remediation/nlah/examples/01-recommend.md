# Example 1 — `recommend` mode (CI/CD pre-merge review)

## Scenario

A developer opens a pull request adding a new `Deployment` manifest. The CI pipeline runs D.6 against the rendered manifest, then runs A.1 in `recommend` mode against D.6's findings. The PR review surfaces the proposed remediation artifacts inline.

**Blast radius**: zero. No cluster access; no patch application. Pure artifact generation.

## Inputs

`auth.yaml` (committed alongside the contract; the safest default):

```yaml
# All defaults: recommend-only, empty allowlist, blast-cap 5.
# Even if the developer flips --mode dry-run, the agent refuses.
```

`contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
source_agent: ci-pipeline
target_agent: remediation
customer_id: cust_acme
task: PR review — remediation recommendations
required_outputs:
  - findings.json
  - report.md
  - artifacts/
budget:
  llm_calls: 0
  tokens: 0
  wall_clock_sec: 60.0
  cloud_api_calls: 0
  mb_written: 10
permitted_tools:
  - read_findings
completion_condition: findings.json AND report.md exist
escalation_rules: []
workspace: /workspaces/cust_acme/remediation/01J7M3X9.../
persistent_root: /persistent/cust_acme/remediation/
created_at: '2026-05-16T12:00:00Z'
expires_at: '2026-05-16T13:00:00Z'
```

D.6's `findings.json` carries 3 findings:

- `run-as-root` on `production/Deployment/frontend` container `nginx`
- `missing-resource-limits` on `production/Deployment/frontend` container `nginx`
- `privileged-container` on `production/DaemonSet/node-exporter` container `exporter`

## Invocation

```bash
uv run remediation run \
    --contract /tmp/contract.yaml \
    --findings /workspaces/cust_acme/k8s_posture/.../findings.json \
    --mode recommend
```

## Stage trace

1. **INGEST** — read_findings parses 3 ManifestFindings.
2. **AUTHZ** — `filter_authorized_findings`:
   - `run-as-root` → action class `K8S_PATCH_RUN_AS_NON_ROOT` exists; **but** `authorized_actions=[]` → refused with `"action_type='...' not in authorized_actions allowlist"`.
   - `missing-resource-limits` → same; refused.
   - `privileged-container` → no v0.1 action class → refused with `"no v0.1 action class for rule_id='privileged-container'"`.
   - Result: 0 authorized, 3 refused.
3. **GENERATE** — empty (no authorized findings). No artifacts.
   4-7. **Skipped** (recommend mode never executes; also no artifacts to dry-run).

## Outputs

`audit.jsonl` (5 entries; hash-chained):

```
remediation.run_started        {mode: recommend, ...}
remediation.findings_ingested  {count: 3, ...}
remediation.action_refused     {rule_id: run-as-root, reason: "not in authorized_actions allowlist"}
remediation.action_refused     {rule_id: missing-resource-limits, ...}
remediation.action_refused     {rule_id: privileged-container, reason: "no v0.1 action class"}
remediation.run_completed      {outcome_counts: {refused_unauthorized: 3}, total_actions: 0}
```

`findings.json`: 3 OCSF 2007 records, each with outcome `refused_unauthorized`. `report.md`: per-outcome summary showing all 3 refusals; no artifacts.

## What the operator does next

The PR review surfaces the report. The developer either:

- **Accepts the recommendations** and updates the manifest themselves (e.g., adds `runAsNonRoot: true` and resource limits to the PR).
- **Allowlists the actions in `auth.yaml`** so the next CI run actually generates the artifacts. Production execution still requires `mode_execute_authorized: true`, gated by the security team.

## Why this matters

`recommend` mode is the **zero-blast-radius bootstrap path** for adopting A.1. Operators can run A.1 against every detect-agent run from day one without any cluster-side risk. The audit chain proves nothing was attempted; the refused outcomes are the operator's TODO list.
