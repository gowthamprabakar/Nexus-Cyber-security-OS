# Scan an AWS account for identity risk — operator runbook

Owner: identity-agent on-call · Audience: a human operator with read-only access to the target AWS account · Last reviewed: 2026-05-11.

This runbook walks through a one-shot Identity Agent scan against a real AWS account, end to end. The scan emits OCSF v1.3 Detection Findings (`class_uid 2004`) into the charter workspace.

---

## Prerequisites

- A working `uv sync` of this repository.
- A read-only AWS profile authorized to call the IAM and Access Analyzer APIs in the target account:
  - `iam:List*` (Users, Roles, Groups, AttachedPolicies, InlinePolicyNames, GroupsForUser, GroupMembership).
  - `access-analyzer:ListFindingsV2` (optional — skipped if you don't pass `--analyzer-arn`).
- An `ExecutionContract` YAML for the run (see Section 2).
- (Optional) the set of IAM user _names_ known to have MFA. In Phase 1 this comes from cloud-posture's helpers or your existing AWS Config / CIS-benchmark export.

The agent **never writes** to AWS — every call is a `List*` / `Get*`. You can run this in any account without staging permissions.

---

## 1. Pick a profile + region

The agent treats IAM as global but boto3 needs a region for client construction. Use the region you already have credentials for.

```bash
export AWS_PROFILE=prod-readonly
export AWS_REGION=us-east-1
```

For Access Analyzer, the analyzer is regional. If your account has analyzers in multiple regions, run the agent once per region (or feed multiple contracts to a supervisor).

---

## 2. Author an ExecutionContract

The contract is what the charter enforces. Minimal shape:

```yaml
schema_version: '0.1'
delegation_id: '01J7M3X9Z1K8RPVQNH2T8DBHFZ' # ULID; uuidgen + ULID-encode
source_agent: 'operator-cli'
target_agent: 'identity'
customer_id: 'cust_acme'
task: 'Identity posture scan of AWS account 123456789012'
required_outputs:
  - 'findings.json'
  - 'summary.md'
budget:
  llm_calls: 1
  tokens: 1
  wall_clock_sec: 300.0
  cloud_api_calls: 200
  mb_written: 10
permitted_tools:
  - 'aws_iam_list_identities'
  - 'aws_iam_simulate_principal_policy'
  - 'aws_access_analyzer_findings'
completion_condition: 'findings.json AND summary.md exist'
escalation_rules: []
workspace: '/tmp/nexus-identity/cust_acme/run-2026-05-11/ws'
persistent_root: '/tmp/nexus-identity/cust_acme/run-2026-05-11/p'
created_at: '2026-05-11T12:00:00+00:00'
expires_at: '2026-05-11T12:05:00+00:00'
```

Save to `/tmp/identity-scan.yaml`.

The `cloud_api_calls: 200` budget is sized to cover the IAM listing + Access Analyzer call overhead. Tight budgets fail with `BudgetExhausted`; if you hit that, double the value and re-run (the registry costs are per-tool-call, not per-API-request).

---

## 3. Compute the MFA-user set

If you don't yet have a programmatic feed, pull the IAM credential report and grep for `mfa_active = true`:

```bash
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d \
  | python -c "
import csv, sys
r = csv.DictReader(sys.stdin)
print(','.join(row['user'] for row in r if row.get('mfa_active') == 'true'))
"
```

Pipe the comma-separated names into `--mfa-user` flags (one per name).

In Phase 1c this becomes a cloud-posture cross-tool — for now it's an operator-supplied input.

---

## 4. Run the agent

```bash
uv run identity-agent run \
    --contract /tmp/identity-scan.yaml \
    --profile prod-readonly \
    --region us-east-1 \
    --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/nexus \
    --mfa-user alice --mfa-user bob --mfa-user carol \
    --dormant-threshold-days 90
```

Expected output:

```
agent: identity (v0.1.0)
customer: cust_acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 7
  critical: 2
  high: 3
  medium: 2
  low: 0
  info: 0
  overprivilege: 2
  external_access: 1
  mfa_gap: 1
  admin_path: 0
  dormant: 3
workspace: /tmp/nexus-identity/cust_acme/run-2026-05-11/ws
```

---

## 5. Read the outputs

Three files in the workspace:

```bash
ls /tmp/nexus-identity/cust_acme/run-2026-05-11/ws/
# findings.json  summary.md  audit.jsonl
```

- **`summary.md`** — start here. The "High-risk principals" section pinned at the top is the 30-second triage. Anything listed there has admin grants, public/cross-account access, or no MFA. Per-severity sections follow with one bullet per finding.
- **`findings.json`** — the OCSF wire format. Hand to fabric / downstream agents. Pretty-print with `jq` if needed.
- **`audit.jsonl`** — hash-chained audit log. Verify integrity with `uv run charter audit verify`.

---

## 6. Triage workflow

| Finding family    | Severity      | Default next step                                                                                                                                                      |
| ----------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mfa_gap`         | Critical      | Enable MFA on the user **immediately**. Auditors will flag any admin-without-MFA in an incident review.                                                                |
| `external_access` | Critical/High | Cross-check the resource policy and the requesting external principal. If unintended → remediate via Tier-2 (Phase 1c).                                                |
| `overprivilege`   | High          | Replace `AdministratorAccess` with a job-function policy (`Billing`, `ViewOnlyAccess`, etc.). Document the exception if the grant is intentional.                      |
| `dormant`         | Medium        | Verify with the owner. If unused for > 6 months → deactivate or delete. Service roles that are intentionally idle can be tagged `service:true` (Phase 2 exempts them). |

The Phase 1 caps below mean the v0.1 driver will under-report some signals — see the README's "Phase 1 caps (deferred)" list.

---

## 7. Common failures

| Symptom                                      | Cause                                                           | Fix                                                               |
| -------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------- |
| `BudgetExhausted: cloud_api_calls`           | Contract budget too low for IAM listing                         | Bump `budget.cloud_api_calls` in the contract (~200 is typical)   |
| `IamListingError: profile-... not found`     | AWS profile name typo or missing config                         | Confirm `aws configure list-profiles` shows the profile           |
| `AccessAnalyzerError: ... AccessDenied ...`  | Profile lacks `access-analyzer:ListFindingsV2`                  | Either grant it, or drop `--analyzer-arn` to skip Access Analyzer |
| No `mfa_gap` findings even though MFA is off | Operator forgot to pass `--mfa-user` flags (or passed too many) | The MFA signal is operator-supplied; verify Section 3             |
| All users flagged as dormant                 | Last-used timestamps missing because the account is brand-new   | Lower `--dormant-threshold-days` only after confirming intent     |

---

## 8. Cleanup

The agent writes only to `workspace` and `persistent_root` — both under `/tmp/nexus-identity/<customer>/<run>` by convention. Delete the run directory once you've exported the report.

```bash
rm -rf /tmp/nexus-identity/cust_acme/run-2026-05-11
```

---

## See also

- [`README`](../README.md) — package overview + ADR-007 v1.1 conformance addendum.
- [D.2 plan](../../../../docs/superpowers/plans/2026-05-11-d-2-identity-agent.md).
- [ADR-002](../../../../docs/_meta/decisions/ADR-002-charter-as-context-manager.md) — audit-chain requirement.
- [ADR-004](../../../../docs/_meta/decisions/ADR-004-fabric-layer.md) — OCSF v1.3 + `NexusEnvelope` wire format.
- [Cloud Posture Agent runbook](../../cloud-posture/runbooks/) — for the CSPM side of the picture (a Phase 1a customer typically runs both).
