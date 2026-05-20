# Example 2 — Cross-account oversharing IAM (MEDIUM, F.3-correlation uplift)

**Input:** A snapshot of S3 bucket inventory for account `123456789012`. Bucket `analytics-export` has a bucket policy granting cross-account `s3:GetObject` to account `999988887777` without an MFA / IP / VPCE / OrgID condition guard.

**Bucket policy** (from `policy_json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOtherAccountRead",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::999988887777:root" },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::analytics-export", "arn:aws:s3:::analytics-export/*"]
    }
  ]
}
```

**No object samples available** (operator only staged the inventory feed). No classifier hits.

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-AWS-OVERSHARE-004-analytics-export
  finding_type: data_security_s3_oversharing_iam
  severity: MEDIUM # no classifier hit → base MEDIUM (no HIGH uplift)
  rule_id: s3_oversharing_iam
  title: S3 bucket analytics-export has oversharing IAM policy
  affected:
    - cloud: aws
      account_id: '123456789012'
      region: us-east-1
      resource_type: s3-bucket
      arn: arn:aws:s3:::analytics-export
  evidence:
    rule: s3_oversharing_iam
    source_finding_type: data_security_s3_oversharing_iam
    overshare_statement_count: 1
    overshare_statement_sids: [AllowOtherAccountRead]
    classifier_labels_found: []
```

**F.3 cross-correlation.** If the operator pinned `--cloud-posture-workspace /tmp/f3-output/` and that workspace contains a `findings.json` with an F.3 finding on the same bucket (e.g., F.3 also flagged `analytics-export` for missing CloudTrail logging), Stage 5 SCORE applies a correlation uplift:

```yaml
# After CORRELATE + SCORE
- finding_id: CSPM-AWS-OVERSHARE-004-analytics-export
  severity: HIGH # MEDIUM uplifted one level via F.3 correlation
  evidence:
    # ... detector evidence unchanged ...
    rule: correlation_uplift # appended in evidences[]
    source: f3_cloud_posture
    original_severity: medium
    uplifted_severity: high
    matched_f3_finding_ids: [CSPM-AWS-PROW-042-analytics-export-no-cloudtrail]
```

**Markdown report layout** (operator-facing, with correlation):

```
# Data Security Agent (D.5) — Run Report

**run_id**: `01J0000000000000000000DSEC`
**total_findings**: 1

**Severity breakdown**:
- **CRITICAL**: 0
- **HIGH**: 1 # uplifted from MEDIUM via F.3 correlation
- **MEDIUM**: 0
- **LOW**: 0
- **INFO**: 0

## Detector breakdown
- `s3_oversharing_iam`: 1

## HIGH (1)
### `CSPM-AWS-OVERSHARE-004-analytics-export` — S3 bucket analytics-export has oversharing IAM policy
- **rule**: `s3_oversharing_iam`
- **severity**: `high`
- **affected resources**:
  - `arn:aws:s3:::analytics-export`
- **classifier labels**: (none)
- **F.3 correlation**: `CSPM-AWS-PROW-042-analytics-export-no-cloudtrail` (severity uplifted)
```

**Why MEDIUM as the detector's base severity?** Cross-account access via S3 bucket policy is a known and sometimes legitimate pattern (data-lake federation, partner integrations). Without classifier evidence of sensitive content, the rule lands at MEDIUM. The CRITICAL escalation requires both signals: oversharing + sensitive content. When operators see HIGH from this rule, it means either F.3 also flagged the bucket (correlation uplift) or the classifier found sensitive content (in-detector uplift).

**Why does the guard-suppression test allow a single MFA / IP / VPCE / OrgID condition to suppress the finding entirely?** Because operators who go to the trouble of writing a guard condition have explicitly evaluated the cross-account exposure. v0.1's conservative posture: presence of a guard = trust the operator. A future v0.2+ refinement could evaluate the specific guard value (e.g., reject `aws:SourceIp=0.0.0.0/0` as not actually a guard), but that's deferred per scope.

**Operator next steps** (we do NOT take these autonomously in v0.1):

1. Verify whether the cross-account grant to `999988887777` is intentional (data-lake federation contract).
2. If intentional, add an MFA / IP / VPCE / OrgID condition — D.5 will then stop flagging.
3. If unintentional, remove the statement from the bucket policy.
4. Stage object samples next run — if classifier hits surface, severity uplifts to HIGH in-detector (without needing F.3 correlation).
5. Hand off to D.7 Investigation Agent if the F.3 correlation appeared — D.7 may stitch this with audit-log activity on the bucket.
