# Tools available to Cloud Posture Agent

All tools are async. Invoke through the charter: `await ctx.call_tool("tool_name", **kwargs)`.
The charter enforces budget, tool-whitelist, and audit logging on every call.

---

## `prowler_scan(account_id, region, output_dir, min_severity?, profile?, timeout?)`

Wraps Prowler 5.x. Returns `ProwlerResult` with `raw_findings: list[dict]` (OCSF-shaped emissions from Prowler).

| Field          | Type  | Default  | Notes                                                                              |
| -------------- | ----- | -------- | ---------------------------------------------------------------------------------- |
| `account_id`   | str   | required | 12-digit AWS account.                                                              |
| `region`       | str   | required | e.g. `us-east-1`. One region per call.                                             |
| `output_dir`   | Path  | required | Where Prowler writes its `*.ocsf.json` output.                                     |
| `min_severity` | str   | `"info"` | Filters Prowler's emissions to `>=` this severity (info/low/medium/high/critical). |
| `profile`      | str?  | `None`   | AWS named profile. Omit to use default credential chain.                           |
| `timeout`      | float | `1800.0` | Seconds. On timeout, Prowler is killed and `ProwlerError` is raised.               |

**Cost:** 10–60s wall clock; no LLM calls.
**When:** First step of any scan, before enrichment.
**Failure:** raises `ProwlerError` on non-zero exit, missing JSON output, or timeout.

---

## `aws_s3_list_buckets(region)`

Returns `list[str]` of bucket names visible to the configured credentials.

**Cost:** 1 AWS API call.
**When:** Listing potential targets for `aws_s3_describe`.

---

## `aws_s3_describe(bucket, region)`

Returns a dict with: `bucket`, `region`, `acl` (Grants list), `policy` (or None), `encryption` (or None), `versioning` (Status string), `public_access_block` (or None), `logging` (LoggingEnabled or None).

The wrapper swallows three "not configured" `ClientError` codes and returns `None` for those fields:

- `NoSuchBucketPolicy`
- `ServerSideEncryptionConfigurationNotFoundError`
- `NoSuchPublicAccessBlockConfiguration`

**Cost:** 6 AWS API calls per bucket.
**When:** Enriching a Prowler S3 finding with primary-source ACL / policy / encryption evidence.

---

## `aws_iam_list_users_without_mfa()`

Returns `list[str]` of usernames that have a console password (login profile present) but no MFA device.

**Cost:** 1 + (N users × 2) AWS API calls.
**When:** Detecting console-enabled users without MFA. Pair with severity=high.

---

## `aws_iam_list_admin_policies()`

Returns `list[dict]` of customer-managed policies that grant `Action="*"` on `Resource="*"`. Each entry: `{policy_name, policy_arn, document}`.

**Cost:** 1 + N policies AWS API calls.
**When:** Detecting admin-equivalent customer-managed policies. Severity=critical.
**Note:** AWS-managed policies are excluded (Scope=Local). Inline policies on roles/users are out of scope for v0.1.

---

## `kg_upsert_asset(kind, external_id, properties)`

Upserts an asset node in the customer's Neo4j knowledge graph. Every MERGE constrains by `customer_id` (set at writer construction time), so cross-tenant data never co-mingles.

| Field         | Notes                                                   |
| ------------- | ------------------------------------------------------- |
| `kind`        | e.g. `aws_s3_bucket`, `aws_iam_user`, `aws_iam_policy`. |
| `external_id` | Primary identifier (ARN preferred).                     |
| `properties`  | Free-form dict; `SET a += $properties` semantics.       |

**Cost:** 1 Cypher round-trip.
**When:** After enriching a resource you intend to reference from a finding.

---

## `kg_upsert_finding(finding_id, rule_id, severity, affected_arns)`

Upserts a `:Finding` node and `(:Finding)-[:AFFECTS]->(:Asset)` edges in one batched query (`UNWIND $arns`).

**Cost:** 1–2 Cypher round-trips (skips the relation query when `affected_arns` is empty).
**When:** After emitting a finding to `findings.json`. The KG write is the persistence side; the OCSF event on the fabric is the wire side.

---

## Out-of-scope tools (planned, not yet wired)

- `prowler_scan_azure` / `prowler_scan_gcp` — Phase 2.
- `aws_kms_list_keys` / `aws_kms_describe_key` — for KMS rotation findings; D.1 work.
- `aws_cloudtrail_status` — for missing-CloudTrail findings; coming with the Audit Agent (F.6).
