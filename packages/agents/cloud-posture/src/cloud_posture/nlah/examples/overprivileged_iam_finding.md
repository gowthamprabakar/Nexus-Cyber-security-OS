# Example: Over-privileged IAM policy (admin-equivalent)

## Source

Prowler may not flag customer-managed admin-equivalent policies on its own. Use `aws_iam_list_admin_policies()` — it returns customer-managed (Scope=Local) policies whose default version contains a statement granting `Action="*"` on `Resource="*"`.

## Sample tool output

```json
[
  {
    "policy_name": "TooBroad",
    "policy_arn": "arn:aws:iam::111122223333:policy/TooBroad",
    "document": {
      "Version": "2012-10-17",
      "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
    }
  }
]
```

## Information you surface

| Field         | Value                                                                                                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `finding_id`  | `CSPM-AWS-IAM-002-toobroad`                                                                                                                                                                 |
| `rule_id`     | `CSPM-AWS-IAM-002`                                                                                                                                                                          |
| `severity`    | `critical` — admin-equivalent grants are unconditionally Critical, regardless of attachment count                                                                                           |
| `title`       | `Customer-managed policy 'TooBroad' grants Action=* Resource=*`                                                                                                                             |
| `description` | `Any principal attached to this policy has admin equivalence. Detach or scope the statement immediately.`                                                                                   |
| `affected`    | One `AffectedResource(cloud="aws", account_id="111122223333", region="us-east-1", resource_type="aws_iam_policy", resource_id="TooBroad", arn="arn:aws:iam::111122223333:policy/TooBroad")` |
| `evidence`    | `{"document": {...the full policy document...}, "attachment_count": <n>}` — include the policy doc and (when easy) the attach count                                                         |

## Compounding signal — when to escalate beyond Critical

If `aws_iam_list_users_without_mfa()` returns _any_ user that is also attached to this policy (directly or via group), surface as a **single Critical finding** describing the chain:

> "Console-enabled user 'alice' has no MFA and is attached to admin-equivalent policy 'TooBroad'. Internet-reachable admin equivalence."

Use `evidence` to carry both data points. Do NOT emit two separate findings for the same compounded risk; that fragments triage.

## OCSF event the driver emits (illustrative)

```json
{
  "category_uid": 2,
  "class_uid": 2003,
  "activity_id": 1,
  "severity_id": 5,
  "severity": "Critical",
  "metadata": { "version": "1.3.0", "product": { "name": "Nexus Cloud Posture" } },
  "finding_info": {
    "uid": "CSPM-AWS-IAM-002-toobroad",
    "title": "Customer-managed policy 'TooBroad' grants Action=* Resource=*",
    "desc": "Any principal attached to this policy has admin equivalence. Detach or scope the statement immediately."
  },
  "compliance": { "control": "CSPM-AWS-IAM-002", "status": "Failed", "status_id": 2 },
  "resources": [
    {
      "type": "aws_iam_policy",
      "uid": "arn:aws:iam::111122223333:policy/TooBroad",
      "cloud_partition": "aws",
      "region": "us-east-1",
      "owner": { "account_uid": "111122223333" }
    }
  ],
  "evidences": [
    {
      "document": {
        "Version": "2012-10-17",
        "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
      }
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
