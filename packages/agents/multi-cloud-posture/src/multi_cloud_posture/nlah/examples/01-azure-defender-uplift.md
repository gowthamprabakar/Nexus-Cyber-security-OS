# Example 1 — Azure Defender uplift to CRITICAL

**Input:** A snapshot of Azure Defender for Cloud assessments for subscription `aaa-bbb`.

**Observation:** One assessment flags `Restrict storage account public access` as **Unhealthy** with severity **High**. The same subscription has an Activity Log entry where `user:bob@external.com` was just granted `Microsoft.Authorization/roleAssignments/write` (role assignment).

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-AZURE-DEFENDER-001-restrict-storage-account-public-access
  finding_type: cspm_azure_defender
  severity: HIGH
  title: Restrict storage account public access
  rule_id: asmt-001-restrict-public-storage
  affected:
    - cloud: azure
      account_id: aaa-bbb
      resource_type: Microsoft.Storage/storageAccounts
      resource_id: /subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1
  evidence:
    kind: assessment
    status: Unhealthy
    assessment_type: BuiltIn
    source_finding_type: cspm_azure_defender

- finding_id: CSPM-AZURE-ACTIVITY-001-microsoft-authorization-roleassignments
  finding_type: cspm_azure_activity
  severity: INFO # Activity Log "Informational" level
  title: Microsoft.Authorization/roleAssignments/write (Succeeded)
  affected: [...]
  evidence:
    kind: activity
    operation_class: iam
    caller: user:bob@external.com
    resource_group: rg1
```

**Markdown report layout** (operator-facing):

```
# Multi-Cloud Posture Scan
- Total findings: **2**

## Per-cloud breakdown
- **Azure**: 2 (Defender: 1 | Activity: 1)
- **GCP**:   0

## Severity breakdown
- **Critical**: 0
- **High**:     1
- **Medium**:   0
- **Low**:      0
- **Info**:     1

## Findings
### High (1)
- CSPM-AZURE-DEFENDER-001-restrict-storage-account-public-access — Restrict storage account public access
  Cloud: azure · Resource: sa1

### Info (1)
- CSPM-AZURE-ACTIVITY-001-microsoft-authorization-roleassignments — IAM role assignment write
  Cloud: azure · Caller: bob@external.com
```

**Why two findings, not one?** D.5 doesn't correlate Defender + Activity Log in v0.1 — that's D.7 Investigation's job. The operator sees both raw signals; D.7 stitches them into one incident.

**Operator next steps** (we do NOT take these autonomously in v0.1):

1. Verify the storage account's network rules (Defender assessment evidence has `unmapped.remediationSteps`).
2. Audit the role assignment in Activity Log evidence (`caller: bob@external.com` is on the customer domain allowlist? if not, flag separately).
3. Hand off to D.7 Investigation Agent — D.5's `findings.json` is a sibling-workspace input.
