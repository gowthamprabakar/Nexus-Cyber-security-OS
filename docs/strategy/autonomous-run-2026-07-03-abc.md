# Autonomous Run — 2026-07-03 — A + B + C (multi-cloud + correlation moat)

**Context:** operator out ~few days; directive "option a + b + c, each in high-level depth." This is the single source of truth for what was done and why. No operator check-ins possible → defensible defaults, documented.

## Operating mode

- Subagent-driven (implementer + per-task review + whole-branch adversarial review), ponytail + devil-critic throughout, husky-clean (no `--no-verify`).
- **Branches + PRs, NO merges** (operator merges on return). No other outward actions unrequested.
- Honest docs; "verified cross-cloud" = a CI test fires the detector on that cloud's fixture, nothing more.

## The three tracks

### A — Mixed-cloud ranking verification (cheap, real) — branch `feat/multi-cloud-attack-paths`

Verify the v0.5 expected-loss ranking produces a coherent top-N on a mixed AWS+Azure+GCP graph (v0.5 tests were AWS-only). Uses the ~10 already-wired cross-cloud archetypes. **Status: DONE (commit `eb6cdaa0`) — `test_mixed_cloud_ranking_e2e.py`, all 3 clouds fire, non-increasing expected-loss, AWS-high-blast outranks single-store; 1 pass.**

### C — Toxic-combination correlation moat (net-new, highest value) — branch `feat/toxic-combo-correlations` (off main)

**Scoped + code-verified.** Two investigations disagreed on whether `CAN_ESCALATE_TO`→data is built; **grep decided**: `CAN_ESCALATE_TO`, `STORES_SECRET`, `USES_SERVICE_ACCOUNT`, `IRSA_MAPPING`, `CONTAINS_PACKAGE`, `PEERED_WITH` all appear **0 times** in `kg_query.py` — none are named detectors. The reframe: these walks ALREADY fire via the **generic engine** (`find_candidate_paths`) as anonymous candidates capped at severity 50 (no title, no fix, buried below confirmed findings). C **promotes them to named, titled, ranked detectors** — the North Star "prioritized" pillar. Pure `kg_query` correlation of already-written edges; zero new writers/readers; CI-REAL (each walk already has an e2e test proving the generic path).

Build (each = new `find_*` + dataclass in `kg_query.py`; `_SEVERITY` + `_title` + `find_all` wiring in `attack_paths.py`; `REMEDIATION` in `attack_path_remediation.py`; `_FIX` in `report_card.py`; `_EXPOSURE_IMPACT` in `test_path_taxonomy.py`; **add the shape to `NAMED_SHAPES` in `path_engine.py`** so the generic engine stops double-listing it; and **update the existing generic e2e test to assert the NAMED detector**; then full-suite green):

1. **`find_stored_secret_to_data`** (~sev 88) — `CLOUD_RESOURCE --STORES_SECRET--> SECRET --OWNED_BY--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. Embedded credential in a running workload. Test: `test_path_stored_secret_e2e.py`.
2. **`find_k8s_escape_to_cloud_data`** (~sev 82) — `K8S_OBJECT{privileged} --USES_SERVICE_ACCOUNT--> SA --IRSA_MAPPING--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. Container escape → cloud data. Test: `test_path_k8s_escape_e2e.py`.
3. **`find_escalation_method_to_data`** (~sev 76) — `IDENTITY --CAN_ESCALATE_TO--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. The ~20 AWS privesc methods; graph-model-scope-map's "#1 gap." Distinct from `find_privilege_escalation_to_data` (ASSUMES = role you can assume vs CAN_ESCALATE_TO = method to grant yourself admin). Test: `test_path_escalation_e2e.py`.

Stretch (if momentum): `find_internet_exposed_sbom_vulnerable` (CONTAINS_PACKAGE) + VPC-peered→data (PEERED_WITH). Deferred: OCSF emission (slice already deferred), SSPM OAuth (needs `SSO_INTO` bridge — new writer). Devil-critique: genuine net-new named paths (grep-confirmed un-named), reuse real edges (not lipstick), each already discovered by the generic engine → promoting them is pure ranking-quality gain. **Cascade risk: naming a generic shape breaks its existing generic-assertion test — must flip each to a named assertion + run full suite for ripples.**
**Status: DONE — PR #794 (NOT merged).** 3 named detectors + full cascade each; opus adversarial review (0 Critical, 3 Important — #1 dedup-key mismatch FIXED, #3 stored-secret scope-clarity FIXED, #2 ASSUMES-vs-CAN_ESCALATE_TO double-count DOCUMENTED-as-accepted). 1051 pass / 0 fail. Commits 9f195c90 / 1013e2d4 / 1e5743e6 / 23a705f7 on `feat/toxic-combo-correlations`.

### B — Azure/GCP KMS/SQL/VM multi-cloud (build, carefully) — branch `feat/multi-cloud-attack-paths`

**Cascade finding (why this is a build, not a verify):** multi-cloud-posture's CIS rule engine (`AZURE_CIS_RULES`/`GCP_CIS_RULES`) is DEAD CODE in the live pipeline (imported only in tests; production uses offline Defender/SCC feeds). Azure Key Vault, Azure VM, GCP Cloud KMS have NO public-exposure rule at all. No Azure/GCP spine writers (like cloud-posture's `record_kms_keys`/`record_rds_instances`/`record_ec2_workloads`); no canonical key builders for Azure Key Vault / GCP KMS. **Least-invasive plan:** build the spine writers + canonical keys + the missing detection logic + CI-REAL injectable-client tests (proves detection cross-cloud); do NOT unilaterally revive the deliberately-dead engine — document the production-emission wiring decision for the operator. **Note:** the detectors are already provider-agnostic (they filter on `kind=="kms-key"`/`"rds-instance"`/`is_public`, cloud-blind), so the net-new work is the WRITERS (map Azure/GCP cloud data → unified-`kind` spine nodes) + canonical keys; "cross-cloud detection" is then proven by planting an Azure/GCP-keyed node with the unified kind and firing the (unchanged) detector. **Status: BUILDING.**

## Decision log

(appended as decisions are made)

- 2026-07-03: sequence A→C→B (value + risk); B's engine-revival is an operator architecture decision, not an autonomous one.
