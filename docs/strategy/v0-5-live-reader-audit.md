# v0.5 Item 3 — Live-Reader Audit (existing vs net-new)

**Date:** 2026-07-03
**Purpose:** determine which `NEXUS_LIVE_*` readers already exist so Item 3 builds only what is genuinely net-new (no rebuilds). This is the definitive net-new list Tasks 11–13 implement.

## Method

- `grep -rhoE "NEXUS_LIVE_[A-Z_]+" packages` — enumerate the live lanes already wired.
- Inspect `packages/agents/network-threat/src/network_threat/tools/` and `packages/agents/identity/src/identity/tools/` for existing reader classes.

## Findings

| Reader (spec §6.1)                | Status      | Evidence                                                                                                                             |
| --------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Identity live AWS IAM             | **EXISTS**  | `NEXUS_LIVE_IDENTITY_AWS` lane; identity D-2 live enumeration                                                                        |
| Identity live Azure AD            | **EXISTS**  | `NEXUS_LIVE_IDENTITY_AZURE` lane; `azure_ad.py` Graph reader                                                                         |
| Network AWS VPC flow              | **EXISTS**  | `NEXUS_LIVE_NETWORK_VPC_AWS` lane; `vpc_flow_realtime_aws.py`                                                                        |
| AppSec live GitHub (secrets feed) | **EXISTS**  | B-1 live `ScmConnector`; `appsec.run(scm_connector=...)`                                                                             |
| **Azure NSG reach**               | **NET-NEW** | no `nsg`/`azure` reader in network-threat tools; `reachability.py` docstring names it "the operator-gated follow-on"                 |
| **GCP firewall reach**            | **NET-NEW** | no `firewall`/`gcp` reach reader in network-threat tools                                                                             |
| **GCP SA-key live reader**        | **NET-NEW** | `sa_key_ownership()` (owner logic) exists in `gcp_iam.py`, but **no live reader** produces `GcpServiceAccountKey` from the cloud API |
| **Azure SP-secret live reader**   | **NET-NEW** | `sp_credential_ownership()` exists in `azure_ad.py`, but **no live reader** produces the SP-credential input from Graph              |

## Net-new build list (Item 3)

Each maps a cloud API's model into an **existing** dataclass/function (detectors + ownership logic already exist and are provider-agnostic), plus an ungated fake-client composition test (CI-proven mapping) and a gated live e2e (operator-run):

1. **Azure NSG reach reader** → `NetworkInstance`/`SecurityGroup` → `reach_grants` — Task 11.
2. **GCP firewall reach reader** → `NetworkInstance`/`SecurityGroup` → `reach_grants` — Task 12.
3. **GCP SA-key live reader** → `GcpServiceAccountKey` → `sa_key_ownership` — Task 13.
4. **Azure SP-secret live reader** → SP-credential input → `sp_credential_ownership` — Task 13.

**Do NOT rebuild** the four EXISTS readers above. The only new plumbing is the four net-new mappers; all downstream logic (reach/ownership/convergence) is already built and tested.

## Honesty note

"Done" for each net-new reader is split: the **mapping** is CI-proven (ungated fake-client test); the **live lane** is operator-run against a real account (`NEXUS_LIVE_*`). No reader is claimed "live-proven" until the operator runs its gated lane.
