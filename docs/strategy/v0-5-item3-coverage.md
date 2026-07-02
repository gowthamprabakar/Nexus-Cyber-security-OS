# v0.5 Item 3 — Live-Reader Coverage Note (Done-Split)

**Date:** 2026-07-03
**Audit source:** `docs/strategy/v0-5-live-reader-audit.md`

## Net-new readers (Tasks 11–13)

| Reader                                                                          | CI-proven mapping                                                                           | Live lane gate     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------ |
| Azure NSG reach (`AzureNsgReader` → `reach_grants`)                             | `packages/agents/network-threat/tests/test_azure_nsg_reader.py`                             | `NEXUS_LIVE_AZURE` |
| GCP firewall reach (`GcpFirewallReader` → `reach_grants`)                       | `packages/agents/network-threat/tests/test_gcp_firewall_reader.py`                          | `NEXUS_LIVE_GCP`   |
| GCP SA-key live reader (`GcpSaKeyReader` → `sa_key_ownership`)                  | `packages/agents/identity/tests/test_gcp_sa_key_reader.py` + `test_gcp_sa_key_ownership.py` | `NEXUS_LIVE_GCP`   |
| Azure SP-secret live reader (`AzureSpSecretReader` → `sp_credential_ownership`) | `packages/agents/identity/tests/test_azure_sp_secret_reader.py`                             | `NEXUS_LIVE_AZURE` |

Gated e2e for all four: `packages/integration/src/fleet_testkit/tests/test_live_readers_gated.py`

## EXISTS readers (not rebuilt — already wired)

Per `docs/strategy/v0-5-live-reader-audit.md`, the following readers existed before v0.5 Item 3
and were explicitly **not rebuilt**:

- **Identity live AWS IAM** — `NEXUS_LIVE_IDENTITY_AWS` lane; identity D-2 live enumeration.
- **Identity live Azure AD** — `NEXUS_LIVE_IDENTITY_AZURE` lane; `azure_ad.py` Graph reader.
- **Network AWS VPC flow** — `NEXUS_LIVE_NETWORK_VPC_AWS` lane; `vpc_flow_realtime_aws.py`.
- **AppSec live GitHub (secrets feed)** — B-1 live `ScmConnector`; `appsec.run(scm_connector=...)`.

## Honesty boundary

No reader is "live-proven" until the operator runs its gated lane against a real cloud account.

The CI suites prove only the **mapping**: a fake injectable client drives the reader through
the exact same code path that a real cloud client would, and the downstream function
(`reach_grants` / `sa_key_ownership` / `sp_credential_ownership`) is exercised on that output.
That is CI-proven. Whether the real cloud API returns data in the expected shape, and whether
the real account has resources to exercise the non-empty path, is operator-verified only.
