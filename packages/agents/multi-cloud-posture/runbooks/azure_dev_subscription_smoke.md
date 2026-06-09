# Azure dev-subscription smoke test (v0.2 live)

Validates the Multi-Cloud Posture Agent against a **real Azure dev subscription** before any customer-facing release. **Do not run against production.** Read-only, **single subscription** (multi-subscription is v0.3).

## Prerequisites

- An Azure subscription designated dev / staging — **never production**.
- A principal with at most **Reader** (and **Security Reader**) — no write actions.
- Azure credentials available via the `DefaultAzureCredential` chain — any of:
  - `az login` (Azure CLI), or
  - a Service Principal via `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`, or
  - a Managed Identity (when running on Azure).
- `AZURE_SUBSCRIPTION_ID` set to the dev subscription.
- Repo synced: `uv sync --all-packages --all-extras`.

## Procedure

### 1. Confirm credentials + scope

```bash
az account show --query id -o tsv          # the subscription the lane will use
export AZURE_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
```

The agent resolves credentials via `--azure-credential-source` (default `chain` = `DefaultAzureCredential`; or `environment` / `managed-identity` / `cli`). No secret material is logged.

### 2. Run the gated live integration tests (read-only)

```bash
NEXUS_LIVE_AZURE=1 uv run pytest \
    packages/agents/multi-cloud-posture/tests/integration/test_agent_azure_live.py -v
```

Expected: subscription discovered, regions enumerated, the credential resolves, and the agent writes a valid OCSF 2003 `findings.json` + a clean audit chain. **Skips cleanly** (with copy-paste setup) if `NEXUS_LIVE_AZURE` is unset or Azure is unreachable.

### 3. Region scoping

```bash
# default: all regions discovered for the subscription
uv run multi-cloud-posture run --contract /tmp/contract.yaml --azure-credential-source chain
# or pin a subset:
uv run multi-cloud-posture run --contract /tmp/contract.yaml --azure-regions eastus,westus
```

### 4. Reading the output

- **Provenance (v0.2).** Each finding's `Source:` is plain: **`Microsoft Defender`** (passthrough) vs **`Nexus-native`** (a CIS-Azure rule Nexus evaluated). `findings.json` carries the same in `evidence.provenance`.
- **Degraded regions.** If a region failed to scan (throttling / transient), `report.md` carries a **`## Degraded regions`** section with a secret-free reason (e.g. `⚠️ eastus — HttpResponseError: 429`). Other regions complete — a degraded region is **not** a run failure.

## Pass criteria

|     |                                                                    |
| --- | ------------------------------------------------------------------ |
| ✅  | Subscription + regions discovered; credential resolves.            |
| ✅  | `findings.json` is valid OCSF 2003; audit chain verifies.          |
| ✅  | Native (`Nexus-native`) vs Defender provenance is plainly visible. |
| ✅  | No write events in the Azure Activity Log during the smoke window. |

## Not covered (v0.3)

Multi-subscription / management-group scope · the full CIS-Azure rule library · removal of the Defender passthrough (WI-D7).
