# Cloud Posture Eval Suite (v0.1)

Each YAML case under [`cases/`](cases/) is a fixture (mocks of Prowler / IAM / S3 tool outputs) plus expected finding counts and severity distribution. The runner [`cloud_posture._eval_local`](../src/cloud_posture/_eval_local.py) loads cases, executes the agent driver against each fixture, and reports pass/fail per case.

This is a **placeholder** until [F.2 Eval Framework v0.1](../../../../docs/superpowers/plans/2026-05-08-build-roadmap.md) extracts the runner into the standalone `eval-framework` package. When that ships, this module is deleted.

## Running locally

```bash
uv run python -c "
from pathlib import Path
from cloud_posture._eval_local import load_cases, run_case

cases = load_cases(Path('packages/agents/cloud-posture/eval/cases'))
results = [run_case(c) for c in cases]
passed = sum(1 for r in results if r.passed)
print(f'{passed}/{len(results)} passed')
for r in results:
    if not r.passed:
        print(f'  FAIL {r.case_id}: {r.failure_reason}')
"
```

A regression-guard test [`test_all_shipped_cases_pass`](../tests/test_eval_local.py) runs the same loop under pytest, so any drift in the agent's finding-shape contract breaks the suite immediately.

## Case schema

```yaml
case_id: 001_descriptive_slug # required; matches filename stem
description: One-sentence intent # required; surfaces in failure reasons

fixture: # tool outputs the agent will see
  prowler_findings: [] # list of raw Prowler OCSF rows (CheckID, Severity, ResourceArn, …)
  iam_users_without_mfa: [] # list of usernames
  iam_admin_policies: [] # list of {policy_name, policy_arn, document}
  s3_buckets: [] # optional

expected:
  finding_count: 0 # required; total findings emitted
  has_severity: # optional; per-severity exact counts
    critical: 0
    high: 0
    medium: 0
    low: 0
    info: 0
```

## Phase-1 trajectory

- **v0.1 (today, 10 cases):** representative AWS CSPM misconfigurations covering the public-bucket / no-MFA / admin-policy / unencrypted-RDS / open-SG / no-CloudTrail / root-account / KMS-rotation / public-snapshot / unencrypted-EBS shapes.
- **Phase 1 target: ≥ 100 cases per agent** ([build-roadmap.md](../../../../docs/superpowers/plans/2026-05-08-build-roadmap.md), Phase 1 success criteria). Adding cases is a follow-on within F.3 — no new infrastructure required.
- **Cross-provider eval-parity** ([ADR-003](../../../../docs/_meta/decisions/ADR-003-llm-provider-strategy.md)) lands when the agent driver starts calling the LLM. v0.1 Cloud Posture is deterministic so eval results don't depend on model choice.

## Why these ten cases first

They were chosen for **coverage breadth across severity bands and resource types**, not difficulty:

| #   | CheckID family                                 | Severity | Why it matters                                           |
| --- | ---------------------------------------------- | -------- | -------------------------------------------------------- |
| 001 | s3_bucket_public_access                        | high     | Most common cloud-data-exposure pattern                  |
| 002 | iam (no-MFA path)                              | high     | Credential-theft vector; tests the IAM enrichment branch |
| 003 | rds_instance_storage_encrypted                 | high     | Encryption-at-rest baseline                              |
| 004 | ec2_securitygroup_open_22                      | critical | SSH exposed to internet — catastrophic                   |
| 005 | cloudtrail_multi_region                        | high     | Audit blind-spot                                         |
| 006 | iam_root_no_mfa                                | critical | Root account compromise = game over                      |
| 007 | kms_cmk_rotation_enabled                       | medium   | Compliance drift; tests the medium severity path         |
| 008 | iam admin policy (`Action="*"` `Resource="*"`) | critical | Tests the admin-policy enrichment branch                 |
| 009 | rds_snapshots_public_access                    | critical | Public exfil of structured data                          |
| 010 | ec2_ebs_volume_encryption                      | medium   | Volume-level encryption baseline                         |

Together they exercise:

- 4 critical, 4 high, 2 medium → covers the full severity-id mapping (1=info … 5=critical, with 6=fatal collapsing to critical).
- The IAM enrichment branch (cases 002 + 008) — distinct from Prowler-derived findings.
- The Prowler-fallback rule_id path for unmapped CheckIDs (cases 003, 005, 006, 007, 009, 010).
- Six different OCSF resource types: S3 bucket, RDS instance + snapshot, EC2 SG + volume, CloudTrail trail, KMS key, IAM user + policy.
