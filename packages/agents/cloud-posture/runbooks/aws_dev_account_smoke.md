# AWS dev-account smoke test

This runbook validates the Cloud Posture Agent against a **real AWS dev account** before any customer-facing release. **Do not run against production accounts.**

**v0.2 (Level 2 — live AWS).** The runbook exercises the deterministic live-AWS flow: credential resolution (boto3 default chain or `--aws-profile`), current-account autodiscovery (STS `get_caller_identity`), region scoping (`--regions`, default = all available), Prowler + IAM enrichment per region, OCSF 2003 emission, the hash-chained audit log, and **partial-scan degradation** (a failed region is recorded, not fatal). Still single-tenant; LLM enrichment and Postgres `SemanticStore` persistence require the library API and are out of scope here. Cross-account / Organizations is deferred to v0.3.

## Goal

Confirm that, against a live AWS account with read-only credentials:

1. Prowler runs to completion under the charter's wall-clock + cloud-API budget.
2. The agent produces a valid `findings.json` (OCSF v1.3 Compliance Findings) and a human-readable `summary.md`.
3. The hash-chained audit log verifies clean.
4. No unintended writes hit the AWS account (CloudTrail audit-trail review).

## Prerequisites

- An AWS account designated as dev / staging — **never production**.
- An IAM role or user with at most **`SecurityAudit` + `ViewOnlyAccess`** managed policies attached. No write actions permitted.
- AWS profile configured locally (`~/.aws/credentials`) — referred to below as `nexus-dev`.
- **Prowler 5.x available on `$PATH`** (the cloud-posture wrapper resolves the binary via `shutil.which("prowler")`; cloud-posture itself does **not** pin the Prowler CLI as a transitive). Install in a separate environment so it doesn't fight with the workspace's `uv sync`:
  ```bash
  pipx install prowler                # recommended; isolates from this repo's venv
  prowler --version                   # expect >= 5.0
  ```
  Alternatives: `pip install --user prowler`, Homebrew (`brew install prowler`), or running through Docker.
- Repo synced:
  ```bash
  uv sync --all-packages --all-extras
  ```

## Procedure

### 1. Confirm read-only

```bash
aws sts get-caller-identity --profile nexus-dev
aws iam simulate-principal-policy \
    --policy-source-arn "$(aws sts get-caller-identity --profile nexus-dev --query Arn --output text)" \
    --action-names iam:DeleteUser s3:DeleteBucket ec2:TerminateInstances \
    --profile nexus-dev
```

Expected: `EvalDecision` is `implicitDeny` (or `explicitDeny`) for every probed action. **If any action returns `allowed`, stop the runbook.** The smoke test must run under a credential set that physically cannot mutate the account.

### 2. Run Prowler standalone (sanity)

```bash
mkdir -p /tmp/prowler-smoke
prowler aws \
    --profile nexus-dev \
    --region us-east-1 \
    --output-formats json-ocsf \
    --output-directory /tmp/prowler-smoke \
    --no-banner
ls /tmp/prowler-smoke/*.ocsf.json
```

Expected: at least one `*.ocsf.json` file is written. If Prowler exits non-zero, fix the credentials / permissions before continuing — the agent will fail the same way and the cause will be the same.

### 3. Build the invocation contract

Save as `/tmp/smoke-contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8SMKZ1
source_agent: supervisor
target_agent: cloud_posture
customer_id: cust_dev_smoke
task: 'Scan AWS dev account us-east-1 for posture issues (smoke run)'
required_outputs: [findings.json, summary.md]
budget:
  # The v0.1 deterministic flow does not call the LLM, but BudgetSpec
  # enforces strictly positive values. Set the LLM dimensions to 1 so the
  # contract validates; the agent never consumes them.
  llm_calls: 1
  tokens: 1
  wall_clock_sec: 300.0
  cloud_api_calls: 1000
  mb_written: 50
permitted_tools:
  - prowler_scan
  - aws_s3_list_buckets
  - aws_s3_describe
  - aws_iam_list_users_without_mfa
  - aws_iam_list_admin_policies
completion_condition: findings.json exists AND summary.md exists
escalation_rules: []
workspace: /tmp/nexus-smoke/workspace
persistent_root: /tmp/nexus-smoke/persistent
created_at: '2026-05-10T12:00:00+00:00'
expires_at: '2030-01-01T00:00:00+00:00'
```

Validate it:

```bash
uv run charter validate /tmp/smoke-contract.yaml
```

Expected: prints `OK`. If validation fails, fix the YAML before proceeding.

### 4. Run the agent

**v0.2 invocation (recommended).** Omit `--aws-account-id` to **auto-discover** the current account (STS `get_caller_identity`); pass `--aws-profile` for credentials; omit `--regions` to scan **all available regions**, or pass a comma-separated subset:

```bash
uv run cloud-posture run \
    --contract /tmp/smoke-contract.yaml \
    --aws-profile nexus-dev \
    --regions us-east-1,eu-west-1
```

Or pin the account + a single region explicitly (the v0.1-compatible form):

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --profile nexus-dev --query Account --output text)
AWS_PROFILE=nexus-dev uv run cloud-posture run \
    --contract /tmp/smoke-contract.yaml \
    --aws-account-id "$ACCOUNT_ID" \
    --aws-profile nexus-dev \
    --regions us-east-1
```

> **Budget note (v0.2):** Prowler costs ~200 cloud-API calls **per region**. The sample contract's `cloud_api_calls: 1000` covers ~4 regions; **size it up** (or narrow `--regions`) for an all-regions scan, or the run will stop on `BudgetExhausted`.

Expected output (numbers will vary by account state):

```
agent: cloud_posture (v0.2.0)
customer: cust_dev_smoke
run_id: 01J7M3X9Z1K8RPVQNH2T8SMKZ1
findings: 12
  critical: 1
  high: 4
  medium: 5
  low: 2
  info: 0
workspace: /tmp/nexus-smoke/workspace
```

### 5. Verify outputs

```bash
ls /tmp/nexus-smoke/workspace/
head -60 /tmp/nexus-smoke/workspace/summary.md
jq '.findings | length, .findings[0].class_uid, .findings[0].nexus_envelope.tenant_id' \
    /tmp/nexus-smoke/workspace/findings.json
uv run charter audit verify /tmp/nexus-smoke/workspace/audit.jsonl
```

Expected:

- `findings.json`, `summary.md`, `audit.jsonl` all present in the workspace.
- `summary.md` opens with `# Cloud Posture Scan` and lists per-severity counts.
- Every finding has `class_uid: 2003` (OCSF Compliance Finding) and a `nexus_envelope` with the expected `tenant_id`.
- `charter audit verify` reports the chain is **valid**.

**Reading degraded-scan markers (v0.2).** If a region failed to scan (throttling, an invalid region, a per-region permission/connectivity issue), `summary.md` carries a **`## Degraded regions`** section listing each failed region with a **secret-free, traceback-free** reason (e.g. `⚠️ us-bogus-1 — ClientError: Throttling`). The other regions' findings are still emitted — a degraded region is **not** a run failure. Treat an _unexpected_ degraded region as a credential / permission / connectivity issue to investigate, not a hard fail.

### 5b. (Optional) Run the gated live-AWS integration tests

The v0.2 integration tests run the agent end-to-end against the same account and assert the OCSF 2003 shape + audit-chain validity + degraded behavior. They **skip** unless enabled:

```bash
AWS_PROFILE=nexus-dev NEXUS_LIVE_AWS=1 uv run pytest \
    packages/agents/cloud-posture/tests/integration/test_agent_aws_live.py -v
```

Expected: the suite passes — or skips cleanly with a copy-paste setup message if `NEXUS_LIVE_AWS` is unset or AWS is unreachable.

### 6. Review CloudTrail for unintended writes

In the AWS console or via CLI, inspect CloudTrail for the smoke window:

```bash
aws cloudtrail lookup-events \
    --profile nexus-dev \
    --start-time "$(date -u -v-15M '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '15 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    --query 'Events[?ReadOnly==`false`].[EventTime,EventName,Resources]'
```

Expected: empty list. **Any non-read event during the smoke window is a hard fail** — capture the event and file a P0 issue against the agent.

### 7. Cleanup

```bash
rm -rf /tmp/nexus-smoke /tmp/prowler-smoke /tmp/smoke-contract.yaml
```

## Pass criteria

|     |                                                                                                                                                             |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ✅  | Findings count is reasonable for the dev account (not zero unless the account is genuinely clean; not above 500 unless the account is intentionally noisy). |
| ✅  | Every finding's `resources[0].uid` is a syntactically valid AWS ARN.                                                                                        |
| ✅  | `charter audit verify` reports the chain is intact.                                                                                                         |
| ✅  | Required outputs (`findings.json`, `summary.md`) are present and non-empty.                                                                                 |
| ✅  | Wall clock is under the contract's 300-second budget.                                                                                                       |
| ✅  | CloudTrail shows zero non-read events during the smoke window.                                                                                              |
| ✅  | The agent's exit code is 0 — no exceptions, no charter violations.                                                                                          |

## When this runbook fails

1. **Capture artifacts:** stderr, the entire `audit.jsonl`, the Prowler raw `*.ocsf.json`, and `findings.json` (if produced). Sanitize any account IDs / ARNs that aren't safe to share.
2. **File the bug** using `.github/ISSUE_TEMPLATE/bug.yml`. Include the failing rule_id (or "no findings" with the account context if the issue is no detection).
3. **Add a regression eval case** under `packages/agents/cloud-posture/eval/cases/` that replays the failure with mocked tool outputs, so the regression has a test before any fix lands.
4. **Re-run** after the fix; the same runbook should now pass.

## What this runbook does NOT cover

- LLM-driven enrichment or narration (deferred to the Synthesis Agent in [Track D](../../../../docs/superpowers/plans/2026-05-08-build-roadmap.md)).
- Postgres `SemanticStore` knowledge-graph persistence (requires `semantic_store` argument to `cloud_posture.agent.run`; see the library API). The legacy Neo4j writer at `cloud_posture/tools/neo4j_kg.py` is preserved DORMANT against the Phase-2 swap per the KG-loop-closure plan + ADR-009 amendment (2026-05-18).
- **Cross-account / multi-account** scans (STS `AssumeRole`, Organizations, Control Tower) — deferred to **v0.3**. _Multi-**region** is supported in v0.2 via `--regions`._
- Tier-2 / Tier-1 remediation (Track A).
- Production-grade rate-limit / blast-radius checks (the smoke is single-shot; production deployments add Cloud Custodian gating).

These will get their own runbooks as those subsystems land.
