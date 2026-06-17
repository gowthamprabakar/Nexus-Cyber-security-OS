# Example 3 — Cross-source aggregation on CIS 2.1.4

**Input:** Both an F.3 Cloud Posture workspace AND a D.5 Data Security workspace, both emitting findings against an S3 bucket that violates account-level Block Public Access.

**Observation:** Each sibling reports its own view of the same bucket:

- **F.3** emits `CSPM-AWS-S3-001` for the bucket (the F.3 public-access detector).
- **D.5** emits `s3_bucket_public` for the bucket (the D.5 public-bucket detector).

**Mapping** (`s3_bucket_public` AND `CSPM-AWS-S3-001` both map to CIS 2.1.4):

```yaml
- control_id: '2.1.4'
  level: level_1
  required: true
  source_mappings:
    - source_agent: cloud_posture
      source_rule_id: CSPM-AWS-S3-001
    - source_agent: data_security
      source_rule_id: s3_bucket_public
```

**Correlation (Stage 3):** Both correlators emit a per-mapping finding for CIS 2.1.4 (two raw emits):

- F.3 correlator: `COMPLIANCE-CIS_AWS_V3-2_1_4-001-f3_<hash>` (severity HIGH).
- D.5 correlator: `COMPLIANCE-CIS_AWS_V3-2_1_4-001-d5_<hash>` (severity HIGH).

**Aggregation (Stage 4) — the cross-source roll-up:** Both raw emits collapse to a single aggregated ComplianceFinding for CIS 2.1.4 with **two contributors**:

```yaml
finding_id: COMPLIANCE-CIS_AWS_V3-2_1_4-001-aggregated
finding_type: compliance_cis_aws_v3_2_1_4
severity: HIGH # max(HIGH, HIGH) = HIGH
compliance: { control: cis_aws_v3:2.1.4, status_id: 2 }
evidence:
  aggregated_status: FAIL
  contributor_count: 2
  contributing_finding_ids:
    - COMPLIANCE-CIS_AWS_V3-2_1_4-001-f3_<hash>
    - COMPLIANCE-CIS_AWS_V3-2_1_4-002-d5_<hash>
  contributing_source_findings:
    - { agent: cloud_posture, finding_id: 'CSPM-AWS-S3-001-...', rule_id: 'CSPM-AWS-S3-001' }
    - { agent: data_security, finding_id: 'CSPM-AWS-PUBLIC-001-...', rule_id: 's3_bucket_public' }
  control: { framework: cis_aws_v3, control_id: '2.1.4', level: level_1, required: true }
resources:
  # Both sibling resources unioned by arn-dedup. If F.3 + D.5 saw
  # the same bucket, only one resource row remains.
  - { type: aws_s3_bucket, uid: 'arn:aws:s3:::company-secrets', ... }
```

**Why this matters for the auditor.** The aggregated evidence block carries **two distinct sibling perspectives** on the same control failure:

1. **F.3's view** is infrastructure-as-code-shaped: which S3 bucket policy / Block Public Access setting was wrong.
2. **D.5's view** is data-shaped: what sensitive data was potentially exposed (classifier labels in D.5's `evidence.classifier_labels_found`; D.9 doesn't carry those substrings forward but the linkage is preserved via `source_finding.finding_id`).

D.7 Investigation can follow either pointer back to its original sibling-agent finding for the full context. D.9 v0.2 will expose this multi-source linkage to the posture-deltas report so auditors can see whether a control fixed itself across both surfaces or only one.

**Markdown report row:**

> ### High (1)
>
> - `COMPLIANCE-CIS_AWS_V3-2_1_4-001-aggregated` — CIS 2.1.4: Block public access at the S3 account level
>   (2 contributing source-findings: F.3 + D.5)
