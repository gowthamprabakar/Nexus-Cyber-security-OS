# Azure AD / Entra live scan (v0.2 live)

Validates the Identity Agent's **live Azure AD / Entra scanning** against a **real
Azure dev tenant** before any customer-facing release. **Do not run against
production.** Read-only, **single tenant** (multi-tenant → v0.3, Q6).

## Prerequisites

- An Azure tenant designated dev / staging — **never production**.
- A principal with **Microsoft Graph `Directory.Read.All`** (read-only) — no write.
- Azure credentials via the `DefaultAzureCredential` chain — `az login`, a Service
  Principal (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`), or a
  Managed Identity.
- Repo synced: `uv sync --all-packages --all-extras`.

## Procedure

### 1. Confirm credentials + scope

```bash
az account show --query '{tenant:tenantId, user:user.name}'   # confirm the dev tenant
```

Identity resolves the Azure credential through its **`AzureCredentialResolver`**
(`identity.credentials_azure`), which subclasses the **hoisted charter
`CredentialResolver`** — the same `DefaultAzureCredential` shape D.5 uses (Task 9). It
acquires a Microsoft Graph token; no secret material is logged.

### 2. Run the gated live Azure-AD lane (read-only)

```bash
NEXUS_LIVE_IDENTITY_AZURE=1 \
    uv run pytest packages/agents/identity/tests/integration -k azure -v
```

The lane is gated on acquiring a Microsoft Graph token via the resolver and **skips
cleanly** unless `NEXUS_LIVE_IDENTITY_AZURE=1` and Azure is reachable. The Graph
enumeration covers **users + groups + service principals + managed identities**
(`servicePrincipalType == "ManagedIdentity"`), plus **federation** (federated domains

- tenant OIDC identity providers), via the `@odata.nextLink`-paging `GraphReader`.

### 3. Expected output

- Azure AD findings are **OCSF `class_uid 2004`** (the same Detection-Finding wire
  shape as AWS — but coverage is measured **separately**, never aggregated, WI-I1).
- Federation findings (`federation` type) for SAML federated domains + OIDC IdPs.
- Per-collection Graph failures (e.g. a denied `servicePrincipals` read) → secret-free
  degraded markers (`{section, error}`, the hoisted Pattern E); the scan continues. A
  total/credential failure raises `AzureAdListingError`.

## Out of scope at v0.2 (deferred to v0.3)

- Conditional Access + PIM policy evaluation (Q3).
- Per-app workload identity federation (`federatedIdentityCredentials`, e.g.
  GitHub → managed identity) — tenant-level OIDC IdPs only at v0.2 (WI-I6).
- Multi-tenant (Q6); deep cross-cloud federation chains (Q5).
