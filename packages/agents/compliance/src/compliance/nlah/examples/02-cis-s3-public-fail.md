# Example 2 — CIS 2.1.4 + 2.1.5 (S3 BPA) FAIL via D.5 Data Security

**Input:** A D.5 Data Security workspace where the public-bucket detector emitted `s3_bucket_public` for `company-secrets`.

**Observation:** D.5's `findings.json` contains an OCSF v1.3 Compliance Finding (`class_uid 2003`; D.5 re-uses F.3's `build_finding`) with:

```yaml
class_uid: 2003
finding_info:
  uid: CSPM-AWS-PUBLIC-001-company-secrets
compliance:
  control: s3_bucket_public # D.5's short rule_id form
severity_id: 4 # HIGH
evidence:
  source_finding_type: data_security_s3_bucket_public # D.5 discriminator
  rule: s3_bucket_public
  ...
resources:
  - type: aws_s3_bucket
    uid: arn:aws:s3:::company-secrets
```

> D.5 stamps the short rule_id (`s3_bucket_public`) into `compliance.control`. D.6 joins on that field. The full `DataSecurityFindingType.value` (`data_security_s3_bucket_public`) lives in `evidence.source_finding_type` but D.6 doesn't read from there in v0.1.

**Mapping** (from `control_libraries/cis_aws_v3.yaml` — `s3_bucket_public` lands on TWO controls):

```yaml
- control_id: '2.1.4' # Block public access at the S3 account level
  source_mappings:
    - source_agent: data_security
      source_rule_id: s3_bucket_public

- control_id: '2.1.5' # Block public ACLs and policies on individual buckets
  source_mappings:
    - source_agent: data_security
      source_rule_id: s3_bucket_public
```

**Correlation (Stage 3):** Two per-mapping ComplianceFindings emitted — one for CIS 2.1.4, one for CIS 2.1.5.

**Aggregation (Stage 4):** Each control has one contributor → two aggregated emits.

**Scored emits (Stages 5 + 6):**

```yaml
- finding_id: COMPLIANCE-CIS_AWS_V3-2_1_4-001-aggregated
  finding_type: compliance_cis_aws_v3_2_1_4
  severity: HIGH # Level 1 + required
  compliance: { control: cis_aws_v3:2.1.4, status_id: 2 }
  evidence:
    aggregated_status: FAIL
    contributor_count: 1
    contributing_source_findings:
      - {
          agent: data_security,
          finding_id: CSPM-AWS-PUBLIC-001-company-secrets,
          rule_id: s3_bucket_public,
        }
    control: { framework: cis_aws_v3, control_id: '2.1.4', level: level_1, required: true }
  resources:
    - { type: aws_s3_bucket, uid: 'arn:aws:s3:::company-secrets' }

- finding_id: COMPLIANCE-CIS_AWS_V3-2_1_5-002-aggregated
  finding_type: compliance_cis_aws_v3_2_1_5
  severity: HIGH # Level 1 + required
  compliance: { control: cis_aws_v3:2.1.5, status_id: 2 }
  evidence: # same shape as above; control_id = "2.1.5"
    ...
```

**Markdown report row (per-severity section):**

> ### High (2)
>
> - `COMPLIANCE-CIS_AWS_V3-2_1_4-001-aggregated` — CIS 2.1.4: Block public access at the S3 account level
> - `COMPLIANCE-CIS_AWS_V3-2_1_5-002-aggregated` — CIS 2.1.5: Block public ACLs and policies on individual buckets

**One source-finding → multiple control failures.** This is the canonical multi-mapping shape: a single misconfiguration (public S3 bucket) violates multiple defense-in-depth controls in the framework. The aggregator preserves both verdicts so the auditor sees the full impact.
