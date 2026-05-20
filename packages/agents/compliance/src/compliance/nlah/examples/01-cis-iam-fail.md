# Example 1 — CIS 1.10 (IAM MFA) FAIL via F.3 Cloud Posture

**Input:** An F.3 Cloud Posture workspace where the IAM scanner emitted `CSPM-AWS-IAM-001` (user without MFA).

**Observation:** F.3's `findings.json` contains an OCSF v1.3 Compliance Finding (`class_uid 2003`) for the user `alice`:

```yaml
class_uid: 2003
finding_info:
  uid: CSPM-AWS-IAM-001-alice
compliance:
  control: CSPM-AWS-IAM-001
severity_id: 4 # HIGH
resources:
  - type: aws_iam_user
    uid: arn:aws:iam::123456789012:user/alice
    cloud_partition: aws
    region: us-east-1
    owner: { account_uid: '123456789012' }
```

**Mapping** (from `control_libraries/cis_aws_v3.yaml`):

```yaml
control_id: '1.10'
name: Enable MFA for every IAM user with a console password
level: level_1
required: true
source_mappings:
  - source_agent: cloud_posture
    source_rule_id: CSPM-AWS-IAM-001
```

**Correlation (Stage 3, deterministic):** F.3's `compliance.control = "CSPM-AWS-IAM-001"` hits the index under `("cloud_posture", "CSPM-AWS-IAM-001")` → CIS 1.10. One per-mapping ComplianceFinding emitted.

**Aggregation (Stage 4):** Only one contributor → aggregated emit with `contributor_count = 1`.

**Scored emit (Stages 5 + 6):**

```yaml
finding_type: compliance_cis_aws_v3_1_10
severity: HIGH # Level 1 + required = canonical HIGH
title: CIS 1.10 — Enable MFA for every IAM user with a console password
finding_id: COMPLIANCE-CIS_AWS_V3-1_10-001-aggregated
class_uid: 2003
compliance:
  control: cis_aws_v3:1.10
  status_id: 2 # OCSF Failed
evidence:
  aggregated_status: FAIL
  contributor_count: 1
  contributing_finding_ids:
    - COMPLIANCE-CIS_AWS_V3-1_10-001-f3_<8-char-hash>
  contributing_source_findings:
    - agent: cloud_posture
      finding_id: CSPM-AWS-IAM-001-alice
      rule_id: CSPM-AWS-IAM-001
  control:
    framework: cis_aws_v3
    control_id: '1.10'
    level: level_1
    required: true
resources:
  - type: aws_iam_user
    uid: arn:aws:iam::123456789012:user/alice
    region: us-east-1
    owner: { account_uid: '123456789012' }
```

**Markdown report pin** (top of report, above per-severity sections):

> **CIS Level 1 failures (1).**
>
> - `COMPLIANCE-CIS_AWS_V3-1_10-001-aggregated` — **HIGH** CIS 1.10: Enable MFA for every IAM user with a console password
>   → 1 contributing source-finding(s)

**Operator next steps** (we do NOT take these autonomously in v0.1):

1. Enable an MFA device for IAM user `alice` (console password is configured but MFA is not).
2. Re-run the F.3 scan to confirm the finding is cleared.
3. D.6 v0.2 will produce a PASS-finding when the control re-evaluates clean, suitable for auditor attestation export.
