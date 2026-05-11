# Example 2 — Clean account (no findings)

A small, well-governed AWS account: two users with MFA + scoped grants, one service role for Lambda, no Access-Analyzer findings. This is the "happy path" the agent must handle without false positives.

## Inputs

`IdentityListing`:

```python
IdentityListing(
    users=(
        IamUser(arn="arn:aws:iam::123456789012:user/bob",   ..., last_used_at=NOW,
                attached_policy_arns=("arn:aws:iam::aws:policy/ReadOnlyAccess",)),
        IamUser(arn="arn:aws:iam::123456789012:user/carol", ..., last_used_at=NOW,
                attached_policy_arns=("arn:aws:iam::aws:policy/job-function/Billing",)),
    ),
    roles=(
        IamRole(arn="arn:aws:iam::123456789012:role/LambdaExecution", ..., last_used_at=NOW),
    ),
    groups=(),
)
```

Simulator output: every decision is either `allowed` on non-wildcard actions (e.g. `s3:GetObject`) or `implicitDeny` on admin actions. No `iam:*` allow rows. `users_with_mfa = frozenset({"bob", "carol"})`.

Access Analyzer: `aws_access_analyzer_findings(...) → ()`.

## Output

`findings.json`:

```json
{
  "agent": "identity",
  "agent_version": "0.1.0",
  "customer_id": "cust_acme",
  "run_id": "run_2",
  "scan_started_at": "2026-05-11T12:00:00+00:00",
  "scan_completed_at": "2026-05-11T12:00:01+00:00",
  "findings": []
}
```

`summary.md`:

```markdown
# Identity Scan

- Customer: `cust_acme`
- Run ID: `run_2`
- Scan window: 2026-05-11T12:00:00+00:00 → 2026-05-11T12:00:01+00:00
- Total findings: **0**

## Summary

No identity risk detected in this scan window.
```

## Why this shape

- The normalizer must not emit MFA-gap findings for users without admin grants — MFA hygiene matters only when the user _can_ do damage.
- The normalizer must not emit dormancy findings for principals used today.
- A zero-finding scan is a valid and common output. Downstream consumers must handle the empty-findings path without special-casing.
