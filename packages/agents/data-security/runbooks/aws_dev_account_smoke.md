# AWS S3 data-security scan — operator runbook

Owner: data-security on-call · Audience: a cloud-security operator / SRE with read access to AWS S3 (`s3:ListBucket`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketLocation`, `s3:GetBucketTagging`, `s3:GetEncryptionConfiguration`, `s3:GetPublicAccessBlock`, `s3:GetObject` for the sampled keys) · Last reviewed: 2026-05-20.

This runbook walks an operator through pointing the Data Security Agent (D.5) at the two v0.1 feeds — S3 bucket inventory + S3 object samples — optionally cross-correlating against a sibling F.3 cloud-posture workspace, interpreting the OCSF Compliance Findings it emits, and routing the findings into the rest of the Nexus pipeline (D.7 Investigation, A.1 Remediation, F.6 Audit).

> **Status:** v0.1. Live boto3 SDK calls + RDS / DynamoDB / Azure Blob / GCP Storage / Snowflake / Bedrock / Vertex ship in D.5 v0.2 → v0.5+ per the [2026-05-20 version-roadmap](../../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md). v0.1 reads operator-pinned filesystem snapshots and emits findings only — no autonomous remediation, no live AWS API calls beyond the ones the operator runs themselves to stage the feeds.

---

## Prerequisites

- A working `uv sync` of this repository.
- **At least one** of the two feeds:
  - S3 bucket-inventory JSON.
  - S3 object-sample JSON.
- An `ExecutionContract` YAML for the run.
- Optional: a sibling F.3 cloud-posture workspace directory containing `findings.json` for cross-correlation severity uplift.

The agent **never writes** to AWS. Every call is a filesystem read — safe to run against snapshots copied off production.

**Q6 privacy contract.** The classifier returns a label only; matched substrings (SSN digits, card numbers, etc.) NEVER appear in `findings.json` or `report.md`. The render-layer Q6 assert runs as a backstop. If a regression accidentally leaks PII into output, the run fails fast with `SummarizerQ6Violation`.

---

## 1. Stage the feeds

### 1a. S3 bucket inventory

Walk every bucket in the account; stitch per-bucket metadata into a single JSON file matching the `{"buckets": [...]}` shape:

```bash
# Helper: list buckets, then stitch per-bucket metadata.
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | \
while read -r BUCKET; do
  REGION=$(aws s3api get-bucket-location --bucket "$BUCKET" --query LocationConstraint --output text)
  ACL=$(aws s3api get-bucket-acl --bucket "$BUCKET" 2>/dev/null || echo '{}')
  PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" 2>/dev/null || echo '{}')
  ENC=$(aws s3api get-bucket-encryption --bucket "$BUCKET" 2>/dev/null || echo '{}')
  POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null || echo '')
  TAGS=$(aws s3api get-bucket-tagging --bucket "$BUCKET" 2>/dev/null || echo '{}')
  jq -n \
    --arg name "$BUCKET" \
    --arg region "${REGION:-us-east-1}" \
    --arg account "$ACCOUNT" \
    --argjson acl "$ACL" \
    --argjson pab "$PAB" \
    --argjson enc "$ENC" \
    --arg policy "$POLICY" \
    --argjson tags "$TAGS" \
    '{name: $name, region: $region, account_id: $account,
      acl: {grants_all_users: ($acl.Grants | map(select(.Grantee.URI=="http://acs.amazonaws.com/groups/global/AllUsers")) | map(.Permission)),
            grants_authenticated_users: ($acl.Grants | map(select(.Grantee.URI=="http://acs.amazonaws.com/groups/global/AuthenticatedUsers")) | map(.Permission))},
      public_access_block: ($pab.PublicAccessBlockConfiguration // {block_public_acls: true, ignore_public_acls: true, block_public_policy: true, restrict_public_buckets: true}),
      encryption: {algorithm: ($enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "NONE")},
      policy_json: (if $policy=="" then null else $policy end),
      tags: ($tags.TagSet // [] | from_entries(map({key: .Key, value: .Value})))}'
done | jq -s '{buckets: .}' > /tmp/s3-inventory.json
```

The reader supports two top-level shapes: `{"buckets": [...]}` canonical and bare list. Per-bucket validation failures are dropped silently (forgiving — mirrors F.3 / multi-cloud-posture pattern).

### 1b. S3 object samples

Sample object content from the buckets you want to scan. Per Q6 + PRD §7.1.4 the cap is **16 KiB per sample**:

```bash
# Sample N keys per bucket. Adjust BUCKETS + N as needed.
BUCKETS=("corp-data-lake" "analytics-export")
N=10
true > /tmp/s3-objects.json

for BUCKET in "${BUCKETS[@]}"; do
  aws s3api list-objects-v2 --bucket "$BUCKET" --max-items "$N" \
    --query 'Contents[].Key' --output text | tr '\t' '\n' | \
  while read -r KEY; do
    # Fetch first 16 KiB, base64-encode.
    SAMPLE=$(aws s3api get-object --bucket "$BUCKET" --key "$KEY" \
              --range bytes=0-16383 /dev/stdout 2>/dev/null | base64)
    jq -n --arg bucket "$BUCKET" --arg key "$KEY" --arg sample "$SAMPLE" \
      '{bucket: $bucket, key: $key, content_sample_b64: $sample}'
  done
done | jq -s '{objects: .}' > /tmp/s3-objects.json
```

The reader caps samples at 16 KiB (`MAX_SAMPLE_BYTES`). Oversized samples are dropped silently.

**Q6 reminder.** The sample bytes leave the reader as part of the returned tuple. The agent driver passes them to `classify()` and discards the reference immediately after the label returns. The reader itself does NOT log or persist the bytes.

---

## 2. Stage the optional F.3 cross-correlation workspace

Skip this section if you don't have a sibling F.3 cloud-posture run for the same account.

If you do, the F.3 workspace contains a `findings.json` whose bucket ARNs we can match against ours. When a D.5 finding matches an F.3 finding on the same `arn:aws:s3:::<bucket>`, the **scorer** uplifts severity one level (cap CRITICAL) and appends a `correlation_uplift` evidence entry.

```bash
# Workspace structure expected by --cloud-posture-workspace:
/tmp/f3-output/
├── findings.json    # F.3 cloud-posture output
└── report.md        # F.3 operator report (not read by D.5)
```

---

## 3. Author the ExecutionContract YAML

```yaml
schema_version: '0.1'
delegation_id: '01J7M3X9Z1K8RPVQNH2T8DBHFZ' # 26-char ULID
source_agent: supervisor
target_agent: data_security
customer_id: acme
task: 'AWS S3 data-security scan, prod account 123456789012'
required_outputs: [findings.json, report.md]
budget:
  llm_calls: 1
  tokens: 1
  wall_clock_sec: 120.0
  cloud_api_calls: 0 # offline-mode v0.1
  mb_written: 50
permitted_tools:
  - read_s3_inventory
  - read_s3_objects
  - read_f3_findings
completion_condition: 'findings.json AND report.md exist'
escalation_rules: []
workspace: /tmp/d5-run-out
persistent_root: /tmp/d5-run-persistent
created_at: '2026-05-20T09:00:00Z'
expires_at: '2026-05-20T10:00:00Z'
```

---

## 4. Run the agent

```bash
uv run data-security run \
    --contract /tmp/contract.yaml \
    --s3-inventory-feed /tmp/s3-inventory.json \
    --s3-objects-feed /tmp/s3-objects.json \
    --cloud-posture-workspace /tmp/f3-output/
```

Sample output (one-line digest):

```
agent: data_security (v0.1.0)
customer: acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 4
  critical: 1
  high: 2
  medium: 1
  low: 0
  info: 0
workspace: /tmp/d5-run-out
```

Run with no feeds → empty report + a one-line warning to stderr. The agent always emits all three artifacts in the workspace.

---

## 5. Interpret the three artifacts

Inside `workspace` (here `/tmp/d5-run-out`) you'll find:

- **`findings.json`** — OCSF v1.3 `class_uid 2003` Compliance Finding array wrapped in a `FindingsReport`. Identical wire shape to F.3 / multi-cloud-posture / k8s-posture. D.7 Investigation + A.1 Remediation consume this.
- **`report.md`** — operator markdown report. CRITICAL pinned above HIGH / MEDIUM / LOW / INFO. The **Q6 render-layer assert** ran during render; if any classifier-matched PII pattern leaked into a finding's title / desc / evidence, the run would have failed with `SummarizerQ6Violation`.
- **`audit.jsonl`** — hash-chained F.6 audit log. Records every tool call + write + completion event. F.6 `audit-agent query` reads it.

### Severity-escalation rules (deterministic, no LLM)

| Detector                                    | Base severity | CRITICAL/HIGH escalation                                          |
| ------------------------------------------- | ------------- | ----------------------------------------------------------------- |
| `s3_bucket_public`                          | HIGH          | CRITICAL with any classifier hit (non-NONE label) in same bucket. |
| `s3_bucket_unencrypted`                     | MEDIUM        | HIGH with any classifier hit.                                     |
| `s3_object_sensitive_in_untrusted_location` | HIGH          | (no further uplift in-detector — classifier hit IS the trigger)   |
| `s3_oversharing_iam`                        | MEDIUM        | HIGH with any classifier hit.                                     |

Plus the cross-stage uplift in Stage 5 SCORE: any D.5 finding with at least one matching F.3 finding on the same bucket ARN bumps one severity level (cap CRITICAL).

---

## 6. Route findings into the pipeline

- **D.7 Investigation Agent.** Pin `--cloud-posture-workspace` to F.3's workspace AND point D.7 at D.5's workspace; D.7 reads `findings.json` from both, stitches them onto a single timeline.
- **A.1 Remediation Agent.** D.5's `findings.json` is a valid A.1 input. v0.1 A.1 handles a subset of these (e.g., block public access on flagged buckets) under Tier-3 / Tier-2 / Tier-1 modes per the A.1 safety contract.
- **F.6 Audit.** Already wired implicitly via the charter. `audit-agent query --run-id <delegation_id>` returns the hash-chained event log.

---

## 7. Failure taxonomy

| Symptom                                             | Likely cause                                                                              | Fix                                                                                                                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `S3InventoryReaderError: ... not found`             | inventory JSON path wrong                                                                 | Recheck `--s3-inventory-feed`.                                                                                                                               |
| `S3InventoryReaderError: ... malformed`             | inventory JSON is not valid JSON                                                          | `jq . /tmp/s3-inventory.json` to validate.                                                                                                                   |
| Findings array empty despite obvious public buckets | inventory feed was empty or buckets dropped at validation                                 | Check per-bucket fields match `BucketInventory` shape; check operator output.                                                                                |
| All findings stay HIGH (never CRITICAL)             | no object samples staged → no classifier hits                                             | Stage `--s3-objects-feed`.                                                                                                                                   |
| **`SummarizerQ6Violation` at end of run**           | **Q6 leak — a finding's title / desc / evidence contains classifier-matched PII content** | **STOP. Treat as P0 bug. Capture findings.json + report.md state, file a regression issue. Do NOT bypass the assert — it's the load-bearing privacy guard.** |
| `data-security eval` returns < 10/10                | regression in detector / classifier / summarizer                                          | Run `uv run pytest packages/agents/data-security -v` for per-test diagnostics.                                                                               |

---

## 8. What we never do

- **Block public access autonomously.** D.5 emits findings; A.1 Remediation acts under its safety contract.
- **Read live AWS APIs.** v0.1 is filesystem-only. v0.2 introduces live boto3 calls behind the same async wrapper signature.
- **Return matched substrings.** Q6 invariant — the classifier API is type-locked to `-> ClassifierLabel`. Detector / scorer / summarizer surface label tokens only.
- **Cross-tenant queries.** Every reader call carries the contract's tenant scope.
- **Auto-discover sibling agents.** F.3 correlation requires explicit `--cloud-posture-workspace`.
- **Mutate AWS state.** D.5 is detect-only. A.1 Remediation owns the mutate path.
