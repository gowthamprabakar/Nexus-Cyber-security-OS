# GCP dev-project smoke test (v0.2 live)

Validates the Multi-Cloud Posture Agent against a **real GCP dev project** before any customer-facing release. **Do not run against production.** Read-only, **single project** (multi-project / organization scope is v0.3).

## Prerequisites

- A GCP project designated dev / staging — **never production**.
- A principal with at most **Viewer** (and **Security Reviewer**) — no write actions.
- GCP credentials available via Application Default Credentials (ADC) — any of:
  - `gcloud auth application-default login`, or
  - a Service-Account key via `GOOGLE_APPLICATION_CREDENTIALS`, or
  - Workload Identity Federation (when running federated).
- `GOOGLE_CLOUD_PROJECT` set to the dev project.
- Repo synced: `uv sync --all-packages --all-extras`.

## Procedure

### 1. Confirm credentials + scope

```bash
gcloud config get-value project
export GOOGLE_CLOUD_PROJECT="$(gcloud config get-value project)"
```

The agent resolves credentials via `--gcp-credential-source` (default `adc`; or `service-account` / `workload-identity`). ADC covers SA-key (dev) and WIF (prod) in one chain. No secret material is logged.

### 2. Run the gated live integration tests (read-only)

```bash
NEXUS_LIVE_GCP=1 uv run pytest \
    packages/agents/multi-cloud-posture/tests/integration/test_agent_gcp_live.py -v
```

Expected: project discovered, regions enumerated, ADC resolves, and the agent writes a valid OCSF 2003 `findings.json` + a clean audit chain. **Skips cleanly** (with copy-paste setup) if `NEXUS_LIVE_GCP` is unset or GCP is unreachable. The Azure and GCP lanes are independent — enabling one never triggers the other.

### 3. Region scoping

```bash
# default: all regions discovered for the project
uv run multi-cloud-posture run --contract /tmp/contract.yaml --gcp-credential-source adc
# or pin a subset:
uv run multi-cloud-posture run --contract /tmp/contract.yaml --gcp-regions us-central1,us-west1
```

### 4. Reading the output

- **Provenance (v0.2).** Each finding's `Source:` is plain: **`Google Security Command Center`** (passthrough) vs **`Nexus-native`** (a CIS-GCP / IAM rule Nexus evaluated). `findings.json` carries the same in `evidence.provenance`.
- **Degraded regions.** A region that failed to scan surfaces in `report.md`'s **`## Degraded regions`** section with a secret-free reason (e.g. `⚠️ us-central1 — TooManyRequests: 429`); other regions complete.

## Pass criteria

|     |                                                               |
| --- | ------------------------------------------------------------- |
| ✅  | Project + regions discovered; ADC resolves.                   |
| ✅  | `findings.json` is valid OCSF 2003; audit chain verifies.     |
| ✅  | Native (`Nexus-native`) vs SCC provenance is plainly visible. |
| ✅  | No write events in Cloud Audit Logs during the smoke window.  |

## Not covered (v0.3)

Multi-project / folder / organization scope · the full CIS-GCP rule library · removal of the SCC passthrough (WI-D7).
