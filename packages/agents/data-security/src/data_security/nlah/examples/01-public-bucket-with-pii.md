# Example 1 — Public bucket with PII (CRITICAL uplift via classifier hit)

**Input:** A snapshot of S3 bucket inventory + object samples for account `123456789012`.

**Observation:** Bucket `corp-data-lake` grants `AllUsers: READ` in its ACL (public) and contains object samples that match SSN + email classifier patterns.

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-AWS-PUBLIC-001-corp-data-lake
  finding_type: data_security_s3_bucket_public
  severity: CRITICAL # base HIGH + classifier hit uplift
  rule_id: s3_bucket_public
  title: S3 bucket corp-data-lake is publicly accessible
  affected:
    - cloud: aws
      account_id: '123456789012'
      region: us-east-1
      resource_type: s3-bucket
      arn: arn:aws:s3:::corp-data-lake
  evidence:
    rule: s3_bucket_public
    source_finding_type: data_security_s3_bucket_public
    acl_grants_all_users: [READ]
    acl_grants_authenticated_users: []
    block_public_access:
      block_public_acls: false
      ignore_public_acls: false
      block_public_policy: false
      restrict_public_buckets: false
    classifier_labels_found: [email, ssn] # LABELS ONLY — NEVER the matched text (Q6)

- finding_id: CSPM-AWS-SENSLOC-003-corp-data-lake
  finding_type: data_security_s3_object_sensitive_in_untrusted_location
  severity: HIGH
  rule_id: s3_object_sensitive_in_untrusted_location
  title: Sensitive data in untrusted S3 bucket corp-data-lake
  affected: [...]
  evidence:
    rule: s3_object_sensitive_in_untrusted_location
    source_finding_type: data_security_s3_object_sensitive_in_untrusted_location
    classifier_labels_found: [email, ssn]
    sensitivity_tag_key: Sensitivity
    trusted_tag_value: Restricted
    actual_tag_value: null # no Sensitivity tag → untrusted by default
    all_tags: {}
```

**Markdown report layout** (operator-facing):

```
# Data Security Agent (D.5) — Run Report

**run_id**: `01J0000000000000000000DSEC`
**total_findings**: 2

**Severity breakdown**:
- **CRITICAL**: 1
- **HIGH**: 1
- **MEDIUM**: 0
- **LOW**: 0
- **INFO**: 0

## Detector breakdown
- `s3_bucket_public`: 1
- `s3_object_sensitive_in_untrusted_location`: 1

## CRITICAL (1)
### `CSPM-AWS-PUBLIC-001-corp-data-lake` — S3 bucket corp-data-lake is publicly accessible
- **rule**: `s3_bucket_public`
- **severity**: `critical`
- **affected resources**:
  - `arn:aws:s3:::corp-data-lake`
- **classifier labels**: `email`, `ssn`

## HIGH (1)
### `CSPM-AWS-SENSLOC-003-corp-data-lake` — Sensitive data in untrusted S3 bucket corp-data-lake
- ...
```

**Q6 invariant in action.** Operator sees `email`, `ssn` label tokens — NEVER the matched email address or SSN digit string. The classifier returned `ClassifierLabel.EMAIL` and `ClassifierLabel.SSN`; the matched substrings are discarded inside the classifier and never propagate.

**Why not also fire `s3_oversharing_iam`?** The bucket policy is `null` in this example — only the ACL is public, not the policy. `s3_oversharing_iam` requires a Statement-shaped grant.

**Operator next steps** (we do NOT take these autonomously in v0.1):

1. Tighten Block Public Access immediately — set all four flags to `true`.
2. Audit `acl.grants_all_users` and explicitly revoke `AllUsers:READ`.
3. Hand off to A.1 Remediation Agent for autonomous remediation (Tier-3 = recommend-only artifacts; Tier-2 = approval-gated; Tier-1 = autonomous).
4. Tag the bucket `Sensitivity=Restricted` once content is reviewed — the `s3_object_sensitive_in_untrusted_location` finding clears once the tag is set.
5. Hand off to D.7 Investigation Agent — D.5's `findings.json` is a sibling-workspace input.
