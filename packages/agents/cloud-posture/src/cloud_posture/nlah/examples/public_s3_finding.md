# Example: Public S3 bucket

## Prowler raw

```json
{
  "CheckID": "s3_bucket_public_access",
  "Severity": "high",
  "Status": "FAIL",
  "ResourceArn": "arn:aws:s3:::acme-public",
  "AccountId": "111122223333",
  "Region": "us-east-1",
  "StatusExtended": "Bucket has public ACL grant"
}
```

## Enrichment

Call `aws_s3_describe(bucket="acme-public", region="us-east-1")`. Inspect:

- `acl[*].Grantee.URI` for `http://acs.amazonaws.com/groups/global/AllUsers` or `AllAuthenticatedUsers`.
- `public_access_block` — if all four flags are `True`, the bucket is _not_ actually reachable publicly even with a permissive ACL → downgrade or suppress.
- `policy` — if it explicitly restricts to known IPs / aws:PrincipalAccount, downgrade one tier and note the mitigation.

## Information you surface (the agent driver builds the OCSF event)

| Field         | Value                                                                                                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `finding_id`  | `CSPM-AWS-S3-001-acme-public`                                                                                                                                                |
| `rule_id`     | `CSPM-AWS-S3-001`                                                                                                                                                            |
| `severity`    | `high` (downgrade to `medium` if a restrictive bucket policy is present and explicit; downgrade to `low` if PAB blocks all four axes)                                        |
| `title`       | `S3 bucket 'acme-public' allows public read`                                                                                                                                 |
| `description` | One sentence: which ACL grant or PAB gap causes the exposure, and the named bucket.                                                                                          |
| `affected`    | One `AffectedResource(cloud="aws", account_id="111122223333", region="us-east-1", resource_type="aws_s3_bucket", resource_id="acme-public", arn="arn:aws:s3:::acme-public")` |
| `evidence`    | `{"acl": [grants...], "public_access_block": null, "policy": null}` — the raw SDK response, not a summary                                                                    |

## OCSF event the driver emits (illustrative; you do not write this directly)

```json
{
  "category_uid": 2,
  "class_uid": 2003,
  "activity_id": 1,
  "severity_id": 4,
  "severity": "High",
  "metadata": { "version": "1.3.0", "product": { "name": "Nexus Cloud Posture" } },
  "finding_info": {
    "uid": "CSPM-AWS-S3-001-acme-public",
    "title": "S3 bucket 'acme-public' allows public read",
    "desc": "Bucket has an ACL granting READ to AllUsers and no Public Access Block."
  },
  "compliance": { "control": "CSPM-AWS-S3-001", "status": "Failed", "status_id": 2 },
  "resources": [
    {
      "type": "aws_s3_bucket",
      "uid": "arn:aws:s3:::acme-public",
      "cloud_partition": "aws",
      "region": "us-east-1",
      "owner": { "account_uid": "111122223333" }
    }
  ],
  "evidences": [
    {
      "acl": [
        {
          "Grantee": { "URI": "http://acs.amazonaws.com/groups/global/AllUsers" },
          "Permission": "READ"
        }
      ],
      "public_access_block": null,
      "policy": null
    }
  ],
  "nexus_envelope": {
    "correlation_id": "01HZX...",
    "tenant_id": "cust_acme",
    "agent_id": "cloud-posture",
    "nlah_version": "0.1.0",
    "model_pin": "claude-sonnet-4-5",
    "charter_invocation_id": "01HZX..."
  }
}
```
