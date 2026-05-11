# Example 1 — Admin user without MFA

The canonical critical finding: an IAM user with admin-equivalent grants (`iam:*` or `*:*`) and no MFA factor configured. This is the precise shape downstream consumers (control plane, ChatOps S.3) page on.

## Inputs

`IdentityListing`:

```python
IdentityListing(
    users=(
        IamUser(
            arn="arn:aws:iam::123456789012:user/alice",
            name="alice",
            user_id="AIDAxxxxALICE",
            create_date=datetime(2024, 1, 1, tzinfo=UTC),
            last_used_at=datetime(2026, 5, 10, tzinfo=UTC),
            attached_policy_arns=("arn:aws:iam::aws:policy/AdministratorAccess",),
            group_memberships=("admins",),
        ),
    ),
    roles=(),
    groups=(...),
)
```

Simulator output (one decision shown):

```python
SimulationDecision(
    principal_arn="arn:aws:iam::123456789012:user/alice",
    action="iam:*",
    resource="*",
    decision="allowed",
    matched_statement_ids=("AdministratorAccess",),
)
```

MFA signal: `users_with_mfa = frozenset()` (alice not in the set).

## Output

`findings.json` — three findings on the same principal (overprivilege HIGH, mfa-gap CRITICAL; dormant is skipped because `alice.last_used_at` is recent):

```json
{
  "agent": "identity",
  "agent_version": "0.1.0",
  "customer_id": "cust_acme",
  "run_id": "run_1",
  "scan_started_at": "2026-05-11T12:00:00+00:00",
  "scan_completed_at": "2026-05-11T12:00:02+00:00",
  "findings": [
    {
      "class_uid": 2004,
      "class_name": "Detection Finding",
      "severity_id": 4,
      "severity": "High",
      "finding_info": {
        "uid": "IDENT-OVERPRIV-ALICE-001-admin_grants",
        "title": "Overprivileged principal: alice",
        "desc": "User 'alice' has 1 admin-equivalent grant(s) (wildcard or service-wide actions).",
        "types": ["overprivilege"]
      },
      "affected_principals": [
        {
          "type": "User",
          "name": "alice",
          "uid": "arn:aws:iam::123456789012:user/alice",
          "account": {"uid": "123456789012"}
        }
      ],
      "evidences": [
        {
          "admin_action_count": 1,
          "attached_policies": ["AdministratorAccess"],
          "inline_admin": false
        }
      ],
      "nexus_envelope": { "tenant_id": "cust_acme", ... }
    },
    {
      "class_uid": 2004,
      "severity_id": 5,
      "severity": "Critical",
      "finding_info": {
        "uid": "IDENT-MFA-ALICE-001-admin_no_mfa",
        "title": "Admin user without MFA: alice",
        "desc": "User 'alice' has admin-equivalent grants but is not in the MFA-enabled set.",
        "types": ["mfa_gap"]
      },
      "evidences": [{"actions_admin": ["iam:*"], "mfa_enabled": false}],
      "nexus_envelope": { ... }
    }
  ]
}
```

`summary.md` (excerpt):

```markdown
# Identity Scan

- Customer: `cust_acme`
- Run ID: `run_1`
- Total findings: **2**

## High-risk principals (1)

Principals with admin-equivalent grants, external/public access, or no MFA.

- `arn:aws:iam::123456789012:user/alice`

## Findings

### Critical (1)

- `IDENT-MFA-ALICE-001-admin_no_mfa` — Admin user without MFA: alice  
  Type: mfa_gap; Principals: arn:aws:iam::123456789012:user/alice

### High (1)

- `IDENT-OVERPRIV-ALICE-001-admin_grants` — Overprivileged principal: alice  
  Type: overprivilege; Principals: arn:aws:iam::123456789012:user/alice
```

## Why this shape

- The high-risk-principals pin gives an SRE 30-second triage — one ARN to focus on.
- Two findings, not one, because **overprivilege** and **MFA gap** are independent controls. A non-admin user might still get an MFA-gap finding via a future control; an admin with MFA still gets the overprivilege flag.
- Severity ranks MFA-gap above overprivilege because the admin grant _without_ MFA is the actually exploitable state — an attacker with alice's password walks straight into the account.
