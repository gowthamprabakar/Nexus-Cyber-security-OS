# Example 2 — GCP overly-permissive IAM lifted to CRITICAL

**Input:** A snapshot of GCP Cloud Asset Inventory IAM policies for project `proj-xyz`. The contract carries `customer_domain_allowlist=("example.com",)` — the customer's internal email domain.

**Observation:** The IAM binding has `roles/owner` granted to `user:bob@external-vendor.com`. That's a non-allowlisted external user with full administrative control over the project.

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-GCP-IAM-001-roles-owner-user-bob-external-vendor-com
  finding_type: cspm_gcp_iam
  severity: CRITICAL # external user + roles/owner = CRITICAL per the rule table
  title: 'IAM: roles/owner → user:bob@external-vendor.com'
  rule_id: roles-owner
  affected:
    - cloud: gcp
      account_id: proj-xyz
      resource_type: cloudresourcemanager.googleapis.com/Project
      resource_id: //cloudresourcemanager.googleapis.com/projects/proj-xyz
  evidence:
    kind: iam
    role: roles/owner
    member: user:bob@external-vendor.com
    asset_type: cloudresourcemanager.googleapis.com/Project
    reason: >-
      User 'user:bob@external-vendor.com' (external domain 'external-vendor.com')
      granted 'roles/owner' — grants full administrative control to a
      non-allowlisted user.
    source_finding_type: cspm_gcp_iam
```

**Compare to: same role on a customer-domain user**

```yaml
- finding_id: CSPM-GCP-IAM-002-roles-owner-user-alice-example-com
  severity: HIGH # allowlisted domain + roles/owner = HIGH (not CRITICAL)
  evidence:
    role: roles/owner
    member: user:alice@example.com
    reason: User 'user:alice@example.com' granted 'roles/owner' — broad
      administrative access; prefer least-privilege predefined / custom roles.
```

**Compare to: same role on a service account**

```yaml
- finding_id: CSPM-GCP-IAM-003-roles-owner-serviceaccount-pipeline-proj-xyz-iam-gserviceaccount-com
  severity: HIGH # service-account owner = HIGH (CI/automation context)
```

**Compare to: public binding on a low-impact role**

```yaml
- finding_id: CSPM-GCP-IAM-004-roles-storage-objectviewer-allusers
  severity: HIGH # allUsers + any role = HIGH (resource exposed to anonymous)
  evidence:
    role: roles/storage.objectViewer
    member: allUsers
```

**Compare to: public binding on impersonation role**

```yaml
- finding_id: CSPM-GCP-IAM-005-roles-iam-serviceaccountuser-allusers
  severity: CRITICAL # allUsers + impersonation = CRITICAL
  evidence:
    reason: >-
      Public principal 'allUsers' granted impersonation role
      'roles/iam.serviceAccountUser' — anyone on the internet can
      impersonate service accounts.
```

**Operator next steps** (out-of-band; D.5 emits findings only):

1. Revoke the `roles/owner` from `bob@external-vendor.com` immediately.
2. Audit other IAM bindings for the same external domain via Cloud Asset Inventory's `search-all-iam-policies` API.
3. If the binding was added recently, cross-reference with the Activity-Log-equivalent (GCP `gcloud logging read 'protoPayload.methodName="SetIamPolicy"'`) — Phase 1c will land this as a `read_gcp_activity` reader.

**Limits acknowledged in v0.1** (documented in the runbook):

- The bundled flagging rules are simple. Real GCP IAM has hundreds of predefined roles; v0.1 only fires on `roles/owner` + `roles/editor` + impersonation roles. Phase 1c adds a deeper rule table.
- Stale service accounts are NOT detected (requires IAM usage API).
- The customer domain allowlist is contract-pinned per run; there's no shared allowlist registry yet.
