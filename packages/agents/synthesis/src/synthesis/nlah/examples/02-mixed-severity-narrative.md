# Example 02 — mixed-severity narrative

This is a narrative.md output for a run with findings spanning multiple severity bands across two sibling sources (F.3 Cloud Posture + D.6 Compliance).

```markdown
# Synthesis Narrative — acme

_Scan window: 2026-05-21T08:00:00+00:00 → 2026-05-21T08:07:00+00:00_
_Run ID: `01J7M3X9Z1K8RPVQNH2T8DBHFZ`_

## Identity posture

Two IAM users lack MFA on console access, both surfaced by F.3 Cloud Posture against the CIS 1.10 control (high severity). Specifically, `CSPM-AWS-IAM-001-alice` and `CSPM-AWS-IAM-001-bob` are flagged; the corresponding D.6 Compliance roll-up `COMPLY-cis_aws_v3_1.10-2026-05-21` captures the per-control FAIL state. Rotate or enforce MFA on both accounts before the next audit cycle.

_Cited findings: `CSPM-AWS-IAM-001-alice`, `CSPM-AWS-IAM-001-bob`, `COMPLY-cis_aws_v3_1.10-2026-05-21`_

## Storage exposure

One S3 bucket (`arn:aws:s3:::contoso-public-uploads`) is configured with public-read ACLs, triggering F.3 finding `CSPM-AWS-S3-001-contoso-public-uploads` (high severity). The bucket also contains data classified as `ssn` per D.5 transitive classification (surfaced via D.6's data-security correlator); the classifier label is reported here without any matched-substring leakage. Close the bucket policy and audit any exposed objects.

_Cited findings: `CSPM-AWS-S3-001-contoso-public-uploads`, `COMPLY-cis_aws_v3_2.1.1-2026-05-21`_

## Compliance posture

Three CIS Level-1 controls failed this scan window: 1.10 (root MFA), 2.1.1 (S3 public access), and 4.16 (CloudTrail validation). D.6's per-control PASS/FAIL roll-up surfaced these as `class_uid 2003` compliance findings. Level-2 recommendations were not assessed in v0.1.

_Cited findings: `COMPLY-cis_aws_v3_1.10-2026-05-21`, `COMPLY-cis_aws_v3_2.1.1-2026-05-21`, `COMPLY-cis_aws_v3_4.16-2026-05-21`_
```

Note: three sections, each carrying explicit `_Cited findings: ..._` lines after the body. Risk-first prose (state the problem, then the evidence), inline backticked finding IDs, and a directional action prompt at the end of each section.
