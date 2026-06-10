# AWS IAM live scan (v0.2 live)

Validates the Identity Agent's **live AWS IAM / CIEM scanning** against a **real AWS
dev account** before any customer-facing release. **Do not run against production.**
Read-only, **single account / region** (multi-account → v0.3, Q6).

## Prerequisites

- An AWS account designated dev / staging — **never production**.
- A principal with **read-only IAM** (e.g. the AWS-managed `IAMReadOnlyAccess`) — no
  write/delete. Access Analyzer read is optional (only used when an analyzer ARN is supplied).
- AWS credentials via the boto3 default chain — `AWS_PROFILE=<profile>` or env keys.
- Repo synced: `uv sync --all-packages --all-extras`.

## Procedure

### 1. Confirm credentials + scope

```bash
aws sts get-caller-identity        # confirm the dev account + principal
export AWS_PROFILE=dev
```

Identity resolves credentials through the **hoisted charter `CredentialResolver`**
(`identity.credentials`, boto3) — the same seam F.3 uses (Task 5, the canonical
3rd-consumer adoption). Only the profile name is handled; no secret material is logged.

### 2. Run the gated live end-to-end pipeline (read-only)

```bash
AWS_PROFILE=dev NEXUS_LIVE_IDENTITY_AWS=1 \
    uv run pytest packages/agents/identity/tests/integration/test_agent_aws_e2e.py -v
```

Full pipeline (WI-I4): boto3 creds → `CredentialResolver` → live IAM enumeration
(users / roles / groups / customer-managed policies) → effective-grant synthesis →
**OCSF 2004** emission → `findings.json` + `summary.md`. The lane **skips cleanly**
unless `NEXUS_LIVE_IDENTITY_AWS=1` and live AWS is reachable (gated on STS
`get_caller_identity`).

### 3. Expected output

- Findings are **OCSF `class_uid 2004`** Detection Findings: `overprivilege`,
  `dormant`, `external_access` (Access Analyzer), `mfa_gap`, and `federation` (SAML +
  OIDC IdP trusts).
- A markdown `summary.md` pinning high-risk principals above the per-severity sections.
- Per-principal / per-section enumeration failures → secret-free degraded markers
  (`{user|role|group|policy|section, error}`, the hoisted Pattern E); the scan
  continues. A total/credential failure raises `IamListingError`.

## Out of scope at v0.2 (deferred to v0.3)

- Multi-account / AWS Organizations (Q6).
- Effective-permissions simulator + used-vs-granted analysis (Q7 — IAM
  `SimulatePrincipalPolicy` wrapper exists but the per-principal scan is v0.3).
- Deep federation chain traversal (Okta → AWS → assume-role paths, Q5).
- GCP IAM CIEM (Q4).
