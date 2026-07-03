# Multi-Cloud KMS / SQL / VM — What's CI-Proven vs What's Deferred to the Operator

**Date:** 2026-07-03 (autonomous A+B+C run, Track B)
**Branch:** `feat/multi-cloud-attack-paths`

This is the honest done-split for Track B. Read it before assuming "Azure/GCP KMS/SQL/VM attack paths work end-to-end" — they do NOT yet, and the reason is an architecture decision that is the operator's to make.

## What Track B built (CI-proven now)

The KMS/SQL/VM attack-path **detectors were already provider-agnostic** (they filter on `kind=="kms-key"` / `kind=="rds-instance"` / `is_public` + `VULNERABLE_TO`, cloud-blind). The genuinely-missing piece was the **writers** that stamp Azure/GCP resources as spine nodes with those markers, plus canonical keys. Built:

- **Canonical keys** (`charter/canonical.py`): `azure_key_vault_key_uri`, `gcp_kms_key_name`.
- **Spine writers** (`multi_cloud_posture/tools/kg_writer.py`): `record_kms_keys` (B-1), `record_sql_instances` + `record_vm_instances` (B-2) — each stamps a `CLOUD_RESOURCE` with the unified `kind` + `is_public` (+ `EXPOSES_DATA` for KMS).
- **CI-REAL tests**: given Azure/GCP data (injected directly, no live cloud), the writers produce the spine nodes and the four detectors (`find_kms_key_access`, `find_exposed_kms_key`, `find_exposed_database`, `find_internet_exposed_host_vulnerable`) fire on the Azure/GCP-keyed nodes.

So: **the detection logic + the writer mapping are cross-cloud-complete and CI-proven.** Same bar as v0.5's live readers (mapping CI-proven; live emission operator-run).

## What is DEFERRED — and why it's the operator's call, not an autonomous one

**Nothing in the production pipeline calls these writers yet, because the signal source is dead code.** Specifically (verified in the cascade investigation):

1. **Multi-cloud-posture's native CIS rule engine (`AZURE_CIS_RULES` / `GCP_CIS_RULES`, `AzureRuleEngine.evaluate()`) is dead in the live pipeline** — imported only in tests. The production normalizers consume offline Defender / SCC / IAM feeds instead. This appears to be a **deliberate architecture choice** (feeds over native evaluation), so reviving the engine is not a change to make unilaterally.
2. **Three resource types have no public-exposure rule at all:** Azure Key Vault, Azure VM, GCP Cloud KMS (the existing rules check soft-delete / rotation, not public access). Azure SQL, GCP Cloud SQL, GCP Compute DO have public-exposure rules — but they never run (see #1).
3. **These writers therefore have no production caller.** To emit in production, someone must decide the source of the `is_public` signal and wire it.

### The operator decision (two viable paths)

- **Path A — revive + extend the rule engine:** wire `AzureRuleEngine`/`GcpRuleEngine` into the live normalizer path, add the 3 missing public-exposure rules (Key Vault, VM, GCP KMS), and call the B writers from the rule results. Pro: uses the existing rule model. Con: reverses the deliberate offline-feed architecture — needs the operator to confirm _why_ the engine was sidelined.
- **Path B — extract from the offline feeds:** parse the `is_public` / public-network-access signal out of the Defender / SCC findings the pipeline already consumes, and call the B writers from there. Pro: keeps the offline-feed architecture. Con: depends on whether Defender/SCC findings carry a reliable public-exposure signal per resource (needs verification).

Either path is a real, scoped follow-on that touches the multi-cloud-posture agent's core and warrants operator sign-off. Track B intentionally stopped at the CI-proven detection + writer layer and did NOT pick a path.

## Bottom line

Azure/GCP KMS/SQL/VM attack-path **detection is proven cross-cloud in CI.** Production **emission** is one operator decision away (Path A or B above). No lipstick: these paths will not fire against a live Azure/GCP account until that wiring lands.
